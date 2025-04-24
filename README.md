# Ghosting-AMSI

🛡 AMSI Bypass via RPC Hijack (NdrClientCall3)
This technique exploits the COM-level mechanics AMSI uses when delegating scan requests to antivirus (AV) providers through RPC. By hooking into the NdrClientCall3 function—used internally by the RPC runtime to marshal and dispatch function calls—we intercept AMSI scan requests before they're serialized and sent to the AV engine.

🔍 What’s happening under the hood:

Intercepted Arguments: Payloads are manipulated before hitting the AV, tricking AMSI into thinking clean data is being scanned.

Bypassing Detection: Unlike traditional methods that patch AmsiScanBuffer or set internal flags (like amsiInitFailed), this operates one layer deeper—at the RPC runtime itself.

No AMSI.dll Modification: Because AMSI itself isn't touched, this method evades both signature-based and behavior-based detection engines.

💡 Why NdrClientCall3?

rpcrt4.dll!NdrClientCall3 is a low-level function in the RPC runtime responsible for marshaling parameters and sending them to the RPC server.

AMSI’s backend communication with AV providers is likely implemented via auto-generated stubs (from IDL), which call into NdrClientCall3 to perform the actual RPC.

By hijacking this stub, we gain full control over what AMSI thinks it’s scanning.


![Alt text]([https://yourdomain.com/your-image.gif](https://cdn-images-1.medium.com/max/1000/1*XU2nnpQEHZrH7O2g0Uvtew.gif))
