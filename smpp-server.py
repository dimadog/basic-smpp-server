import asyncio
import logging
import struct
from typing import Optional, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('smpp_server')

# SMPP Command IDs
SMPP_COMMANDS = {
    'bind_receiver': 0x00000001,
    'bind_transmitter': 0x00000002,
    'bind_transceiver': 0x00000009,
    'submit_sm': 0x00000004,
    'deliver_sm': 0x00000005,
    'unbind': 0x00000006,
    'generic_nack': 0x80000000,
    'bind_receiver_resp': 0x80000001,
    'bind_transmitter_resp': 0x80000002,
    'bind_transceiver_resp': 0x80000009,
    'submit_sm_resp': 0x80000004,
    'deliver_sm_resp': 0x80000005,
    'unbind_resp': 0x80000006
}

class SMPPPDU:
    def __init__(self, command_id, command_status, sequence_number, body=b''):
        self.command_id = command_id
        self.command_status = command_status
        self.sequence_number = sequence_number
        self.body = body

    def encode(self):
        """Encode PDU for transmission"""
        length = 16 + len(self.body)  # 16 bytes header + body
        return struct.pack(
            '!IIII',
            length,
            self.command_id,
            self.command_status,
            self.sequence_number
        ) + self.body

class SMPPServerProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.bound = False
        self.system_id = None
        self.sequence_number = 1
        self.valid_credentials = {'smppuser': 'password'}

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        logger.info(f"Connection from {peername}")

    def data_received(self, data):
        try:
            pdu = self.parse_pdu(data)
            logger.info(f"Received PDU: {self.command_id_to_name(pdu.command_id)}")
            
            if pdu.command_id == SMPP_COMMANDS['bind_receiver']:
                self.handle_bind(pdu, is_transceiver=False)
            elif pdu.command_id == SMPP_COMMANDS['bind_transmitter']:
                self.handle_bind(pdu, is_transceiver=False)
            elif pdu.command_id == SMPP_COMMANDS['bind_transceiver']:
                self.handle_bind(pdu, is_transceiver=True)
            elif pdu.command_id == SMPP_COMMANDS['submit_sm']:
                self.handle_submit_sm(pdu)
            elif pdu.command_id == SMPP_COMMANDS['unbind']:
                self.handle_unbind(pdu)
            else:
                self.send_generic_nack(pdu, status=0x00000003)  # ESME_RINVCMDID

        except Exception as e:
            logger.error(f"Error processing PDU: {e}")
            self.transport.close()

    def parse_pdu(self, data):
        """Parse SMPP PDU from received data"""
        if len(data) < 16:
            raise ValueError("PDU too short")
        
        length, command_id, command_status, sequence_number = struct.unpack('!IIII', data[:16])
        body = data[16:length]
        
        return SMPPPDU(
            command_id=command_id,
            command_status=command_status,
            sequence_number=sequence_number,
            body=body
        )

    def command_id_to_name(self, command_id):
        """Convert numeric command ID to human-readable name"""
        for name, cmd_id in SMPP_COMMANDS.items():
            if cmd_id == command_id:
                return name
        return f"Unknown command (0x{command_id:08x})"

    def handle_bind(self, pdu, is_transceiver):
        """Handle bind receiver/transmitter/transceiver"""
        # Simplified parsing - real implementation would parse system_id, password, etc.
        if self.authenticate(pdu):
            self.bound = True
            resp_command_id = {
                SMPP_COMMANDS['bind_receiver']: SMPP_COMMANDS['bind_receiver_resp'],
                SMPP_COMMANDS['bind_transmitter']: SMPP_COMMANDS['bind_transmitter_resp'],
                SMPP_COMMANDS['bind_transceiver']: SMPP_COMMANDS['bind_transceiver_resp']
            }[pdu.command_id]
            
            response = SMPPPDU(
                command_id=resp_command_id,
                command_status=0,  # ESME_ROK
                sequence_number=pdu.sequence_number,
                body=b'smppserver\x00'  # system_id
            )
            self.transport.write(response.encode())
        else:
            response = SMPPPDU(
                command_id=SMPP_COMMANDS['generic_nack'],
                command_status=0x0000000D,  # ESME_RBINDFAIL
                sequence_number=pdu.sequence_number
            )
            self.transport.write(response.encode())

    def authenticate(self, pdu):
        """Simple authentication check"""
        # In a real implementation, properly parse system_id and password from PDU body
        return True  # Accept all for this example

    def handle_submit_sm(self, pdu):
        """Handle submit_sm"""
        if not self.bound:
            self.send_generic_nack(pdu, status=0x0000000B)  # ESME_RINVBNDSTS
            return
        
        # Process message (simplified)
        logger.info("Received submit_sm")
        
        # Send response
        response = SMPPPDU(
            command_id=SMPP_COMMANDS['submit_sm_resp'],
            command_status=0,  # ESME_ROK
            sequence_number=pdu.sequence_number,
            body=b'message_id_123\x00'  # message_id
        )
        self.transport.write(response.encode())

    def handle_unbind(self, pdu):
        """Handle unbind"""
        self.bound = False
        response = SMPPPDU(
            command_id=SMPP_COMMANDS['unbind_resp'],
            command_status=0,  # ESME_ROK
            sequence_number=pdu.sequence_number
        )
        self.transport.write(response.encode())
        self.transport.close()

    def send_generic_nack(self, pdu, status):
        """Send generic_nack response"""
        response = SMPPPDU(
            command_id=SMPP_COMMANDS['generic_nack'],
            command_status=status,
            sequence_number=pdu.sequence_number
        )
        self.transport.write(response.encode())

    def connection_lost(self, exc):
        logger.info("Client disconnected")
        if self.transport:
            self.transport.close()

class SMPPServer:
    def __init__(self, host='0.0.0.0', port=2775):
        self.host = host
        self.port = port
        self.server = None

    async def start(self):
        loop = asyncio.get_running_loop()
        self.server = await loop.create_server(
            lambda: SMPPServerProtocol(),
            self.host, self.port)
        
        logger.info(f"SMPP Server running on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("SMPP Server stopped")

async def main():
    server = SMPPServer()
    try:
        await server.start()
    except asyncio.CancelledError:
        await server.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down SMPP server...")
