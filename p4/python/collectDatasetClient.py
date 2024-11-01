import asyncio
import websockets
import os
import signal
import subprocess
from time import sleep

wsPort = 5000
wsAddress = "140.113.61.128"

subprocess.Popen(["pkill","-f","tf_dataset"], start_new_session=True, stdout=subprocess.DEVNULL)
subprocess.Popen(["pkill","-f","bfrt_cp"], start_new_session=True, stdout=subprocess.DEVNULL)


async def run(uri):
    async with websockets.connect(uri) as websocket:
        while True:
            await websocket.send("WAIT_FOR_DATASET_NAME")

            message = await websocket.recv()
            print(f"recv: {message}")
            if message == "COMPLETE":
                break

            parsedMessage = message.split("|")
            className = parsedMessage[1]
            classType = parsedMessage[2]

            tfCommand = f"make tf_dataset_{className}_{classType} -C .."
            bfrtCommand = f"make -C .."

            tfProcess = subprocess.Popen(tfCommand.split(), start_new_session=True, stdout=subprocess.DEVNULL)
            await asyncio.sleep(2)
            bfrtProcess = subprocess.Popen(bfrtCommand.split(), start_new_session=True, stdout=subprocess.DEVNULL)
            await asyncio.sleep(40)
            # await asyncio.sleep(2)
            
            print(f"Prepare to recv {className} {classType}")
            await websocket.send("READY_TO_SEND")

            message = await websocket.recv()
            print(f"recv: {message}") # SEND_COMPLETE

            await asyncio.sleep(30)
            os.killpg(os.getpgid(tfProcess.pid), signal.SIGTERM)
            os.killpg(os.getpgid(bfrtProcess.pid), signal.SIGTERM)
            await asyncio.sleep(10)


            await websocket.send("RECV_COMPLETE")
            await asyncio.sleep(5)



asyncio.get_event_loop().run_until_complete(run(f"ws://{wsAddress}:{wsPort}"))
asyncio.get_event_loop().run_forever()