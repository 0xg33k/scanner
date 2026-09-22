## NVD API Key Setup

This project uses the NVD API to retrieve vulnerability information.

You need your own NVD API key to use the API.

### Step 1 — Request an NVD API Key

Go to the official NVD API key request page:

https://nvd.nist.gov/developers/request-an-api-key

Request an API key using the NVD website.

**Do not use someone else's API key.**

### Step 2 — Copy Your API Key

After receiving your API key, copy it somewhere safe.

Your API key will look similar to:

```text
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**Never post your API key publicly or commit it to GitHub.**

### Step 3 — Set the API Key

The scanner reads the API key from the `NVD_API_KEY` environment variable.

#### Windows PowerShell

Open PowerShell in the project directory and run:

```powershell
$env:NVD_API_KEY="YOUR_API_KEY_HERE"
```

Replace `YOUR_API_KEY_HERE` with your actual NVD API key.

Example:

```powershell
$env:NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Step 4 — Run the Scanner

After setting the environment variable, run:

```powershell
python scan.py
```

The scanner will automatically read the API key from:

```text
NVD_API_KEY
```

### Step 5 — Permanent Environment Variable (Optional)

If you don't want to set the API key every time you open PowerShell, you can save it as a Windows user environment variable:

```powershell
[Environment]::SetEnvironmentVariable(
    "NVD_API_KEY",
    "YOUR_API_KEY_HERE",
    "User"
)
```


### Security Notice

**Never put your NVD API key directly inside `scan.py`.**

Do not do this:

```python
NVD_API_KEY = "YOUR_API_KEY_HERE"
```

Instead, use:

```python
import os

NVD_API_KEY = os.environ.get("NVD_API_KEY")

if not NVD_API_KEY:
    raise RuntimeError(
        "NVD_API_KEY is not set. Please set your NVD API key as an environment variable."
    )
```
