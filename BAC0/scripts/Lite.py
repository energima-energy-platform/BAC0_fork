#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 by Christian Tremblay, P.Eng <christian.tremblay@servisys.com>
# Licensed under LGPLv3, see file LICENSE in this source tree.
#
"""
ReadWriteScript - extended version of BasicScript.py

As everything is handled by the BasicScript, select the additional features you want::

    # Create a class that implements a basic script with read and write functions
    from BAC0.scripts.BasicScript import BasicScript
    from BAC0.core.io.Read import ReadProperty
    from BAC0.core.io.Write import WriteProperty
    class ReadWriteScript(BasicScript,ReadProperty,WriteProperty)

Once the class is created, create the local object and use it::

    bacnet = ReadWriteScript(localIPAddr = '192.168.1.10')
    bacnet.read('2:5 analogInput 1 presentValue)

"""
import typing as t

# --- standard Python modules ---
import weakref
from collections import namedtuple

from ..core.devices.Device import RPDeviceConnected, RPMDeviceConnected
from ..core.devices.Points import Point
from ..core.devices.Trends import TrendLog
from ..core.devices.Virtuals import VirtualPoint
from ..core.functions.Calendar import Calendar
from ..core.functions.cov import CoV
from ..core.functions.DeviceCommunicationControl import DeviceCommunicationControl
from ..core.functions.Discover import Discover
from ..core.functions.GetIPAddr import HostIP
from ..core.functions.Reinitialize import Reinitialize
from ..core.functions.Schedule import Schedule
from ..core.functions.Events import Event
from ..core.functions.Text import TextMixin
from ..core.functions.TimeSync import TimeSync
from ..core.io.IOExceptions import (
    NoResponseFromController,
    NumerousPingFailures,
    Timeout,
    UnrecognizedService,
)
from ..core.io.Read import ReadProperty
from ..core.io.Simulate import Simulation
from ..core.io.Write import WriteProperty
from ..core.utils.notes import note_and_log
from ..infos import __version__ as version

# --- this application's modules ---
from ..scripts.Base import Base
from ..tasks.RecurringTask import RecurringTask
from ..tasks.UpdateCOV import Update_local_COV

try:
    from ..db.influxdb import ConnectionError, InfluxDB

    INFLUXDB = True
except ImportError:
    INFLUXDB = False

from bacpypes.pdu import Address

# ------------------------------------------------------------------------------


@note_and_log
class Lite(
    Base,
    Discover,
    ReadProperty,
    WriteProperty,
    Simulation,
    TimeSync,
    Reinitialize,
    DeviceCommunicationControl,
    CoV,
    Schedule,
    Calendar,
    TextMixin,
    Event
):
    """
    Build a BACnet application to accept read and write requests.
    [Basic Whois/IAm functions are implemented in parent BasicScript class.]
    Once created, execute a whois() to build a list of available controllers.
    Initialization requires information on the local device.

    :param ip='127.0.0.1': Address must be in the same subnet as the BACnet network
        [BBMD and Foreign Device - not supported]

    """

    def __init__(
        self,
        ip: t.Optional[str] = None,
        port: t.Optional[int] = None,
        mask: t.Optional[int] = None,
        bbmdAddress=None,
        bbmdTTL: int = 0,
        bdtable=None,
        ping: bool = True,
        ping_delay: int = 300,
        db_params: t.Optional[t.Dict[str, t.Any]] = None,
        **params,
    ) -> None:
        self._log.info(
            "Starting BAC0 version {} ({})".format(
                version, self.__module__.split(".")[-1]
            )
        )
        self._log.info("Use BAC0.log_level to adjust verbosity of the app.")
        self._log.info("Ex. BAC0.log_level('silence') or BAC0.log_level('error')")

        self._log.debug("Configurating app")
        self._registered_devices = weakref.WeakValueDictionary()

        # Ping task will deal with all registered device and disconnect them if they do not respond.

        self._ping_task = RecurringTask(
            self.ping_registered_devices, delay=ping_delay, name="Ping Task"
        )
        if ping:
            self._ping_task.start()

        if ip is None:
            host = HostIP(port)
            ip_addr = host.address
        else:
            try:
                ip, subnet_mask_and_port = ip.split("/")
                try:
                    mask_s, port_s = subnet_mask_and_port.split(":")
                    mask = int(mask_s)
                    port = int(port_s)
                except ValueError:
                    mask = int(subnet_mask_and_port)
            except ValueError:
                ip = ip

            if not mask:
                mask = 24
            if not port:
                port = 47808
            ip_addr = Address("{}/{}:{}".format(ip, mask, port))
        self._log.info(
            f"Using ip : {ip_addr} on port {ip_addr.addrPort} | broadcast : {ip_addr.addrBroadcastTuple[0]}"
        )

        Base.__init__(
            self,
            localIPAddr=ip_addr,
            bbmdAddress=bbmdAddress,
            bbmdTTL=bbmdTTL,
            bdtable=bdtable,
            **params,
        )
        self._log.info("Device instance (id) : {boid}".format(boid=self.Boid))
        self.bokehserver = False
        self._points_to_trend = weakref.WeakValueDictionary()

        # Announce yourself
        self.iam()

        # Do what's needed to support COV
        self._update_local_cov_task = namedtuple(
            "_update_local_cov_task", ["task", "running"]
        )
        self._update_local_cov_task.task = Update_local_COV(
            self, delay=1, name="Update Local COV Task"
        )
        self._update_local_cov_task.task.start()
        self._update_local_cov_task.running = True
        self._log.info("Update Local COV Task started (required to support COV)")

        # Activate InfluxDB if params are available
        if db_params and INFLUXDB:
            try:
                self.database = (
                    InfluxDB(db_params)
                    if db_params["name"].lower() == "influxdb"
                    else None
                )
                self._log.info(
                    "Connection made to InfluxDB bucket : {}".format(
                        self.database.bucket
                    )
                )
            except ConnectionError:
                self._log.error(
                    "Unable to connect to InfluxDB. Please validate parameters"
                )

    @property
    def known_network_numbers(self):
        """
        This function will read the table of known network numbers gathered by the
        NetworkServiceElement. It will also look into the discoveredDevices property
        and add any network number that would not be in the NSE table.
        """
        if self.discoveredDevices:
            for each in self.discoveredDevices:
                addr, instance = each
                net = addr.split(":")[0] if ":" in addr else None
                if net:
                    try:
                        self.this_application.nse._learnedNetworks.add(int(net))
                    except ValueError:
                        pass  # proabbly a IP address with a specified port other than 0xBAC0

        return self.this_application.nse._learnedNetworks

    def discover(
        self,
        networks: t.Union[str, t.List[int], int] = "known",
        limits: t.Tuple[int, int] = (0, 4194303),
        global_broadcast: bool = False,
        reset: bool = False,
    ):
        """
        Discover is meant to be the function used to explore the network when we
        connect.
        It will trigger whois request using the different options provided with
        parameters.

        By default, a local broadcast will be used. This is required as in big
        BACnet network, global broadcast can lead to network flood and loss of data.

        If not parameters are given, BAC0 will try to :

            * Find the network on which it is
            * Find routers for other networks (accessible via local broadcast)
            * Detect "known networks"
            * Use the list of known networks and create whois request to find all devices on those networks

        This should be sufficient for most cases.

        Once discovery is done, user may access the list of "discovered devices" using ::

            bacnet.discoveredDevices

        :param networks (list, integer) : A simple integer or a list of integer
            representing the network numbers used to issue whois request.

        :param limits (tuple) : tuple made of 2 integer, the low limit and the high
            limit. Those are the device instances used in the creation of the
            whois request. Min : 0 ; Max : 4194303

        :param global_broadcast (boolean) : If set to true, a global broadcast
            will be used for the whois. Use with care.
        """
        if reset:
            self.discoveredDevices = None
        found = []
        _networks = []
        deviceInstanceRangeLowLimit, deviceInstanceRangeHighLimit = limits
        # Try to find on which network we are
        self.what_is_network_number()
        # Try to find local routers...
        self.whois_router_to_network()
        self._log.info("Found those networks : {}".format(self.known_network_numbers))

        if networks:
            if isinstance(networks, list):
                # we'll make multiple whois...
                for network in networks:
                    if network < 65535:
                        _networks.append(network)
            elif networks == "known":
                _networks = self.known_network_numbers.copy()
            else:
                if isinstance(networks, int) and networks < 65535:
                    _networks.append(networks)

        if _networks:
            for network in _networks:
                self._log.info("Discovering network {}".format(network))
                _res = self.whois(
                    "{}:* {} {}".format(
                        network,
                        deviceInstanceRangeLowLimit,
                        deviceInstanceRangeHighLimit,
                    ),
                    global_broadcast=global_broadcast,
                )
                for each in _res:
                    found.append(each)

        else:
            self._log.info(
                "No BACnet network found, attempting a simple whois using provided device instances limits ({} - {})".format(
                    deviceInstanceRangeLowLimit, deviceInstanceRangeHighLimit
                )
            )
            _res = self.whois(
                "{} {}".format(
                    deviceInstanceRangeLowLimit, deviceInstanceRangeHighLimit
                ),
                global_broadcast=global_broadcast,
            )
            for each in _res:
                found.append(each)
        return found

    def register_device(
        self, device: t.Union[RPDeviceConnected, RPMDeviceConnected]
    ) -> None:
        oid = id(device)
        self._registered_devices[oid] = device

    def ping_registered_devices(self) -> None:
        """
        Registered device on a network (self) are kept in a list (registered_devices).
        This function will allow pinging thoses device regularly to monitor them. In case
        of disconnected devices, we will disconnect the device (which will save it). Then
        we'll ping again until reconnection, where the device will be bring back online.

        To permanently disconnect a device, an explicit device.disconnect(unregister=True [default value])
        will be needed. This way, the device won't be in the registered_devices list and
        BAC0 won't try to ping it.
        """
        for each in self.registered_devices:
            if isinstance(each, RPDeviceConnected) or isinstance(
                each, RPMDeviceConnected
            ):
                try:
                    self._log.debug(
                        "Ping {}|{}".format(
                            each.properties.name, each.properties.address
                        )
                    )
                    each.ping()
                    if each.properties.ping_failures > 3:
                        raise NumerousPingFailures

                except NumerousPingFailures:
                    self._log.warning(
                        "{}|{} is offline, disconnecting it.".format(
                            each.properties.name, each.properties.address
                        )
                    )
                    each.disconnect(unregister=False)

            else:
                device_id = each.properties.device_id
                addr = each.properties.address
                name = self.read("{} device {} objectName".format(addr, device_id))
                if name == each.properties.name:
                    each.properties.ping_failures = 0
                    self._log.info(
                        "{}|{} is back online, reconnecting.".format(
                            each.properties.name, each.properties.address
                        )
                    )
                    each.connect(network=self)
                    each.poll(delay=each.properties.pollDelay)

    @property
    def registered_devices(self):
        """
        Devices that have been created using BAC0.device(args)
        """
        return list(self._registered_devices.values())

    def unregister_device(self, device):
        """
        Remove from the registered list
        """
        oid = id(device)
        try:
            del self._registered_devices[oid]
        except KeyError:
            pass

    def add_trend(self, point_to_trend: t.Union[Point, TrendLog, VirtualPoint]) -> None:
        """
        Add point to the list of histories that will be handled by Bokeh

        Argument provided must be of type Point or TrendLog
        ex. bacnet.add_trend(controller['point_name'])
        """
        if (
            isinstance(point_to_trend, Point)
            or isinstance(point_to_trend, TrendLog)
            or isinstance(point_to_trend, VirtualPoint)
        ):
            oid = id(point_to_trend)
            self._points_to_trend[oid] = point_to_trend
        else:
            raise TypeError("Please provide point containing history")

    def remove_trend(
        self, point_to_remove: t.Union[Point, TrendLog, VirtualPoint]
    ) -> None:
        """
        Remove point from the list of histories that will be handled by Bokeh

        Argument provided must be of type Point or TrendLog
        ex. bacnet.remove_trend(controller['point_name'])
        """
        if (
            isinstance(point_to_remove, Point)
            or isinstance(point_to_remove, TrendLog)
            or isinstance(point_to_remove, VirtualPoint)
        ):
            oid = id(point_to_remove)
        else:
            raise TypeError("Please provide point or trendLog containing history")
        if oid in self._points_to_trend.keys():
            del self._points_to_trend[oid]

    @property
    def devices(self) -> t.List[t.Tuple[str, str, str, int]]:
        """
        This property will create a good looking table of all the discovered devices
        seen on the network.

        For that, some requests will be sent over the network to look for name,
        manufacturer, etc and in big network, this could be a long process.
        """
        lst = []
        for device in list(self.discoveredDevices or {}):
            try:
                deviceName, vendorName = self.readMultiple(
                    "{} device {} objectName vendorName".format(device[0], device[1])
                )
            except (UnrecognizedService, ValueError):
                self._log.warning(
                    "Unrecognized service for {} | {}".format(device[0], device[1])
                )
                try:
                    deviceName = self.read(
                        "{} device {} objectName".format(device[0], device[1])
                    )
                    vendorName = self.read(
                        "{} device {} vendorName".format(device[0], device[1])
                    )
                except NoResponseFromController:
                    self._log.warning("No response from {}".format(device))
                    continue
            except (NoResponseFromController, Timeout):
                self._log.warning("No response from {}".format(device))
                continue
            lst.append((deviceName, vendorName, device[0], device[1]))
        return lst  # type: ignore[return-value]

    @property
    def trends(self) -> t.List[t.Any]:
        """
        This will present a list of all registered trends used by Bokeh Server
        """
        return list(self._points_to_trend.values())

    def disconnect(self) -> None:
        self._log.debug("Disconnecting")
        for each in self.registered_devices:
            each.disconnect()
        super().disconnect()

    def __repr__(self) -> str:
        return "Bacnet Network using ip {} with device id {}".format(
            self.localIPAddr, self.Boid
        )

    def __getitem__(self, boid_or_localobject):
        item = self.this_application.objectName[boid_or_localobject]
        if item is None:
            for device in self._registered_devices:
                if str(device.properties.device_id) == str(boid_or_localobject):
                    return device
            self._log.error("{} not found".format(boid_or_localobject))
        else:
            return item
