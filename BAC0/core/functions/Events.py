from typing import Callable, Literal, Optional
from dataclasses import dataclass

from bacpypes.core import deferred
from bacpypes.iocb import IOCB
from bacpypes.pdu import Address
from bacpypes.basetypes import (
    Destination,
    Recipient,
    TimeStamp,
    EventState,
    Date,
    Time,
    DateTime,
)
from bacpypes.constructeddata import Any, ListOf


from bacpypes.apdu import (
    SimpleAckPDU,
    ComplexAckPDU,
    WritePropertyRequest,
    AcknowledgeAlarmRequest,
    GetEventInformationRequest,
    GetEventInformationACK,
    GetEventInformationEventSummary,
)

from bacpypes.apdu import APDU


# --- 3rd party modules ---

from ..io.Read import find_reason

ListOfDestination = ListOf(Destination)

"""

using cov, we build a "context" which is turned into a subscription being sent to 
the destination.

Once the IOCB is over, the callback attached to it will execute (subscription_acknowledged)
and we'll get the answer

"""


@dataclass
class GetEventInformationResult:
    list_of_event_summaries: list[GetEventInformationEventSummary]
    more_events: bool


class EventSubscriptionContext:
    """
    Context used for handling incoming event notifications.
    """

    next_proc_id = 1

    def __init__(
        self,
        address: Optional[str] = None,
        object_identifier: Optional[tuple[str, int]] = None,
        confirmed: bool = True,
        callback: Optional[Callable] = None,
        process_id: Optional[int] = None,
    ):

        self.address = address
        if process_id:
            self.subscriberProcessIdentifier = process_id
        else:
            self.subscriberProcessIdentifier = EventSubscriptionContext.next_proc_id
            EventSubscriptionContext.next_proc_id += 1
        self.monitoredObjectIdentifier = object_identifier
        self.issueConfirmedNotifications = confirmed
        self.callback = callback

    def event_notification(self, apdu):
        """
        Called on incoming events.
        Extracts data from the apdu, constructs the respond according to the
        BACnet-standard.
        """

        notification_vals = dict(
            process_identifier=apdu.processIdentifier,
            initiating_device_id=apdu.initiatingDeviceIdentifier,
            initating_object_id=apdu.eventObjectIdentifier,
            time_stamp=apdu.timeStamp,
            notification_class=apdu.notificationClass,
            priority=apdu.priority,
            eventType=apdu.eventType,
            messageText=apdu.messageText,
            notifyType=apdu.notifyType,
            ack_required=apdu.ackRequired,
            from_state=apdu.fromState,
            to_state=apdu.toState,
            event_values=apdu.eventValues,
        )

        elements = {"source": apdu.pduSource, "notification_vals": notification_vals}
        return elements


class Event:
    """
    Methods for handling BACnet-events. Includes subscribing for event notifications,
    receving event notifications, acknowledging events and asking for existing events.
    """

    def event_subscribe(
        self,
        address: str,
        object_identifier: tuple[Literal["notificationClass", "eventForwarder"], int],
        confirmed: bool = True,
        callback: Optional[Callable] = None,
        process_id: Optional[int] = None,
    ):
        """
        Add this device to the recipient list of given notificationClass or
        eventForwarder. This device, will then receive ConfirmedEventNotification or
        UnconfirmedEventNotification for object related to the notificationClass/
        eventForwarder.
        """
        if object_identifier[0] not in ["notificationClass", "eventForwarder"]:
            raise ValueError(
                """notificationClass and eventForwarder is only objects that have
                recipientList, and only the allowed objects to subscribe to events."""
            )

        context = self.build_event_context(
            address,
            object_identifier,
            confirmed=confirmed,
            callback=callback,
            process_id=process_id,
        )
        
        recipient_list = self._create_recipient_list(
            context.subscriberProcessIdentifier
        )
        request = self._make_recipient_list_request(
            address, object_identifier, recipient_list
        )
        self._send_recipient_list_request(request)

    def build_event_context(
        self,
        address: str,
        object_identifier: tuple[str, int],
        confirmed: bool = True,
        callback: Optional[Callable] = None,
        process_id: Optional[int] = None,
    ):
        """ """
        context = EventSubscriptionContext(
            address=address,
            object_identifier=object_identifier,
            confirmed=confirmed,
            callback=callback,
            process_id=process_id,
        )
        self.event_subscription_contexts[context.subscriberProcessIdentifier] = context

        return context

    def _create_recipient_list(self, p_id: int):
        destination = Destination(
            validDays=[1, 1, 1, 1, 1, 1, 1],  # all days
            fromTime=(0, 0, 0, 0),  # midnight
            toTime=(23, 59, 59, 99),  # all day
            recipient=Recipient(device=("device", self.Boid)),  # this device
            processIdentifier=p_id,  # this process
            issueConfirmedNotifications=True,  # confirmed service please
            transitions=[1, 1, 1],  # all transitions
        )

        return destination

    def _make_recipient_list_request(
        self,
        address: str,
        object_identifier: tuple[str, int],
        recipient: Optional[Destination] = None,
    ):

        # Copying bad practice in BAC0, .read() is defined in a class that always is
        # used with Event-class
        exist_recipients = self.read(
            f"{address} {' '.join(map(str,object_identifier))} recipientList"
        )
        if recipient:
            if any([rec.recipient.device[1] == self.Boid for rec in exist_recipients]):
                new_recipients = exist_recipients
            else:
                new_recipients = exist_recipients + [recipient]
        else:
            new_recipients = [
                rec for rec in exist_recipients if rec.recipient.device[1] != self.Boid
            ]

        request = WritePropertyRequest(
            objectIdentifier=object_identifier,
            propertyIdentifier="recipientList",
            propertyValue=Any(),
        )
        recipient_list = ListOfDestination(new_recipients)
        bacpypes_address = Address(address)
        request.pduDestination = bacpypes_address
        request.propertyValue.cast_in(recipient_list)
        # request.priority = 15

        return request

    def _send_recipient_list_request(self, request, timeout=10):
        iocb = IOCB(request)
        iocb.set_timeout(timeout)
        deferred(self.this_application.request_io, iocb)

        iocb.wait()

        self._check_response(
            iocb, SimpleAckPDU, str(type(request)), request.pduDestination
        )

    def event_unsubscribe(
        self,
        address: str,
        object_identifier: tuple[Literal["notificationClass", "eventForwarder"], int],
    ):
        request = self._make_recipient_list_request(address, object_identifier)
        self._send_recipient_list_request(request)

    def acknowledge_event(
        self,
        address: str,
        process_id: int,
        event_object_id: tuple,
        state_ack: str,
        timestamp_event: TimeStamp,
        ack_source: str,
    ):
        """
        Acknowledge an event.
        """
        request = self._make_ack_request(
            address=address,
            process_id=process_id,
            event_object_id=event_object_id,
            state_ack=state_ack,
            timestamp_event=timestamp_event,
            ack_source=ack_source,
        )
        self._send_ack_request(request)

    def _make_ack_request(
        self,
        address: str,
        process_id: int,
        event_object_id: tuple,
        state_ack: str,
        timestamp_event: TimeStamp,
        ack_source,
    ) -> AcknowledgeAlarmRequest:

        assert state_ack in EventState.enumerations.keys()
        time_now = Time()
        time_now.now()
        date_now = Date()
        date_now.now()

        request = AcknowledgeAlarmRequest(
            acknowledgingProcessIdentifier=process_id,
            eventObjectIdentifier=event_object_id,
            eventStateAcknowledged=state_ack,
            timeStamp=timestamp_event,
            acknowledgmentSource=ack_source,
            timeOfAcknowledgment=TimeStamp(
                dateTime=DateTime(time=time_now, date=date_now)
            ),
        )

        bacpypes_address = Address(address)
        request.pduDestination = bacpypes_address

        return request

    def _send_ack_request(self, request: AcknowledgeAlarmRequest, timeout: int = 10):
        iocb = IOCB(request)
        iocb.set_timeout(timeout)
        deferred(self.this_application.request_io, iocb)

        iocb.wait()
        self._check_response(
            iocb, SimpleAckPDU, str(type(request)), request.pduDestination
        )

    def get_event_information(
        self, address: str, last_object_id: Optional[tuple]
    ) -> GetEventInformationResult:
        """
        Send GetEventInformation-request to device.
        """
        request = self._make_get_event_request(address, last_object_id)
        response = self._send_get_event_request(request)
        result = GetEventInformationResult(
            list_of_event_summaries=response.listOfEventSummaries,
            more_events=response.moreEvents,
        )
        return result

    def _make_get_event_request(
        self, address: str, last_object_id: Optional[tuple]
    ) -> GetEventInformationRequest:
        """
        Make the GetEventRequest.
        """
        request = GetEventInformationRequest()
        if last_object_id:
            request.lastReceivedObjectIdentifier = last_object_id

        bacpypes_address = Address(address)
        request.pduDestination = bacpypes_address

        return request

    def _send_get_event_request(
        self, request: GetEventInformationRequest, timeout: int = 10
    ) -> GetEventInformationACK:
        """
        Send the GetEventRequest. Returns the response.
        """

        iocb = IOCB(request)
        iocb.set_timeout(timeout)
        deferred(self.this_application.request_io, iocb)

        iocb.wait()
        apdu = self._check_response(
            iocb, ComplexAckPDU, "GetEventInformation", request.pduDestination
        )

        return apdu

    def _check_response(
        self, iocb: IOCB, expected_apdu_type: APDU, request_type: str, pdu_destination
    ) -> APDU:
        """
        Checks if respond to request is okay. Errors is logged.
        """
        if iocb.ioResponse:  # successful response
            apdu = iocb.ioResponse

            if not isinstance(apdu, expected_apdu_type):  # expect an ACK
                self._log.warning("Not an ack, see debug for more infos.")
                self._log.debug("Not an ack. | APDU : {} / {}".format(apdu, type(apdu)))
                return
        if iocb.ioError:  # unsuccessful: error/reject/abort
            apdu = iocb.ioError
            reason = find_reason(apdu)
            self._log.warning(
                "No response from controller, APDU Abort Reason : {}".format(reason)
            )
        self._log.info(f"{request_type} request sent to device : {pdu_destination}")

        return apdu
