# ⚙️ fastapi-mpp - Secure API payments for AI agents

[![Download fastapi-mpp](https://img.shields.io/badge/Download%20from-Releases-blue?style=for-the-badge)](https://github.com/NilupulThisaranga/fastapi-mpp/releases)

## 🧩 What this app does

fastapi-mpp is a FastAPI middleware for the Machine Payments Protocol (MPP). It helps your API ask for payment with a 402 Payment Required response, manage secure sessions, and check receipts before it serves protected access.

This project is built for APIs that need machine-to-machine payments. It fits use cases where AI agents, automated tools, or other software clients need to pay before they can use a service.

## 📥 Download fastapi-mpp

Visit the [Releases page](https://github.com/NilupulThisaranga/fastapi-mpp/releases) to download and run this app on Windows.

On that page, look for the latest release and download the Windows file that matches your system. After the download finishes, open the file to start the setup or run the app.

## 🪟 Windows requirements

Before you begin, make sure your Windows PC can run the app.

- Windows 10 or Windows 11
- 64-bit computer
- Internet access
- Permission to open downloaded files
- At least 200 MB of free disk space

If your PC can run modern desktop apps and open files from GitHub Releases, it should work.

## 🚀 Getting started

Follow these steps to use fastapi-mpp on Windows.

1. Open the [Releases page](https://github.com/NilupulThisaranga/fastapi-mpp/releases).
2. Find the latest release at the top of the page.
3. Download the Windows file from the Assets list.
4. Save the file to a folder you can find again, such as Downloads.
5. Open the file after the download finishes.
6. If Windows asks for permission, choose the option that allows the app to run.
7. Follow any on-screen steps to finish setup.
8. Start your FastAPI service that uses the middleware.

## 🔧 What you need to use it

fastapi-mpp works as middleware, so it sits between your API and the client that calls it.

You will usually need:

- A FastAPI app
- A payment flow that understands MPP
- A place to store session data
- A way to validate payment receipts
- A client that can respond to 402 Payment Required

For many users, this means the app works best as part of an API setup that already serves requests from agents or other automated clients.

## 🛡️ Main features

- 402 Payment Required challenges
- Secure session handling
- Receipt validation
- FastAPI middleware integration
- Support for machine-to-machine payment flows
- Built for AI agent use cases
- Clear request gating for paid access
- Simple API-side control over payment checks

## 🧠 How it works

When a client sends a request to your API, fastapi-mpp checks if the request meets your payment rules.

If payment is needed, the middleware can return a 402 Payment Required response. The client then follows the payment steps. After payment, the middleware can validate the receipt and let the request continue.

This flow helps you:

- block unpaid access
- check if a session is valid
- confirm that a receipt is real
- keep payment logic in one place

## 🏗️ Basic setup flow

Use this app with your FastAPI project in this order:

1. Download the release from GitHub.
2. Run or install the Windows file.
3. Add the middleware to your FastAPI app.
4. Set your payment rules.
5. Configure session checks.
6. Add receipt validation.
7. Test the API with a client.
8. Confirm that paid and unpaid requests behave as expected.

## 🧪 Simple use case

A common setup looks like this:

- An AI agent sends a request to your API
- The API checks whether the agent has a valid session
- If not, the API returns 402 Payment Required
- The agent pays through your MPP flow
- The API checks the receipt
- The request is allowed through

This keeps access control tied to payment state, not just login state.

## ⚙️ Suggested configuration

You may see settings for things like:

- session timeout
- receipt check interval
- payment challenge type
- valid receipt format
- protected routes
- open routes
- API key or token values
- MPP endpoint values

Use the settings that match your payment provider and your API design. If you are not sure, start with the default values shown in the app or release notes.

## 🔍 How to know it is working

After setup, test these cases:

- Open route: should load without payment
- Protected route with no session: should return 402
- Protected route with valid receipt: should load
- Expired session: should request payment again
- Bad receipt: should block access

If these cases behave as expected, your middleware is set up correctly.

## 🧯 Common issues

### The file does not open

- Check that the download finished
- Try opening it again from your Downloads folder
- Make sure Windows did not block the file

### The app closes right away

- Run it again with the latest release file
- Check whether another app is already using the same port or service
- Restart Windows and try again

### The API still returns 402

- Check your receipt value
- Make sure the session is still valid
- Confirm the protected route is set up correctly
- Make sure the middleware is enabled in your FastAPI app

### The download looks incomplete

- Delete the partial file
- Download it again from the Releases page
- Wait for the browser to finish before opening it

## 🔐 Security notes

fastapi-mpp is built to help protect paid API access. It uses session checks and receipt validation to reduce unpaid use.

For best results:

- keep receipt checks on the server
- store secrets in a safe place
- use HTTPS for API traffic
- set short session lifetimes for sensitive routes
- review which routes need payment and which do not

## 🧭 Who this is for

This app is a good fit if you want to:

- charge for API access
- protect AI agent endpoints
- use 402 responses in your workflow
- validate payment receipts before serving data
- manage paid sessions in FastAPI

It is aimed at services that need controlled access for software clients, not a general desktop app.

## 📁 Project topics

- agent-economy
- ai-agents
- autonomous-agents
- fastapi
- http-402
- m2m-payments
- machine-payments-protocol
- middleware
- mpp
- python

## 🧩 Example workflow for an API owner

A simple owner flow can look like this:

1. Build your FastAPI endpoint
2. Add fastapi-mpp middleware
3. Mark the route as paid
4. Publish your API to agents or clients
5. Let the middleware handle 402 challenges
6. Verify receipts
7. Allow access after payment
8. Track active sessions for repeat use

## 📌 Download again if needed

If you need the file later, use the [Releases page](https://github.com/NilupulThisaranga/fastapi-mpp/releases) again to download and run this file on Windows

## 🛠️ File names you may see

The release page may show files with names like:

- Windows installer
- Windows ZIP file
- executable file
- release archive

Download the one meant for Windows. If more than one file appears, choose the file listed for your platform and the newest release date

## 📬 What to expect after setup

After you run the app, you should be able to:

- connect it to a FastAPI project
- set payment rules
- protect routes with payment checks
- confirm receipts
- handle paid requests from AI agents or other software clients

## 🪄 Quick start checklist

- [ ] Open the Releases page
- [ ] Download the Windows file
- [ ] Run or install it
- [ ] Add the middleware to FastAPI
- [ ] Set protected routes
- [ ] Test 402 responses
- [ ] Validate a receipt
- [ ] Confirm paid access works