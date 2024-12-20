"""Simple API server for irulescan"""

import asyncio
import os
import sys
import json
from shlex import quote as shlex_quote
from tempfile import mkstemp
from typing import Union


REQUIREMENTS_TXT = """
aiofile
fastapi-slim
python-multipart
uvicorn
uvloop
"""

if __name__ == "__main__":
    print("\n".join([line for line in REQUIREMENTS_TXT.splitlines() if line.strip()]))
    sys.exit(0)

from aiofile import async_open
from fastapi import Body, FastAPI, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from uvicorn.server import logger


class WriteTmpfile:
    """async context manager to write data to a temporary file"""

    def __init__(self, data: str):
        self.__data = data
        self.filename = ""

    async def __aenter__(self):
        fd, tmpfile = mkstemp(suffix=".tcl")
        try:
            async with async_open(tmpfile, "w+") as afp:
                await afp.write(self.__data)
        except Exception:
            logger.error(f"Failed writing to temporary file: {tmpfile}")
            raise HTTPException(
                status_code=500,
                detail="Failed writing to temporary file",
            ) from Exception
        finally:
            os.close(fd)

        self.filename = tmpfile
        return self

    async def __aexit__(self, *args):
        os.remove(self.filename)


async def irulescan(filepath: str) -> Union[dict, list]:
    """executes irulescan check on the given filepath and returns the results or throws an HTTPException"""
    cmd = "RUST_BACKTRACE=full irulescan check "
    cmd += shlex_quote(filepath)
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        logger.error(
            f"irulescan error: returncode:{proc.returncode} stderr: {stderr.decode()}"
        )
        raise HTTPException(status_code=500, detail=stderr.decode())

    return json.loads(stdout.decode())


def decode(data: bytes) -> str:
    """gracefully decodes client submitted bytes, raises a HTTPException otherwise."""
    try:
        return data.decode()
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="UnicodeDecodeError, cannot decode submitted data. Is it text?",
        ) from exc


app = FastAPI(
    openapi_tags=[
        {
            "name": "irulescan",
            "description": "security analyzer for iRules.",
        },
    ],
    description="[irulescan homepage](https://github.com/simonkowallik/irulescan/)",
    title="irulescan",
    version="2.0.0",
    docs_url="/",
)


class Result(BaseModel):
    filepath: str
    warning: list
    dangerous: list


@app.post(
    "/scanfiles/",
    tags=["irulescan"],
    response_model=list[Result],
    responses={
        200: {
            "description": "Returns the irulescan result for all submitted files as JSON object.",
            "content": {
                "application/json": {
                    "example": [
                        {"filepath": "ok.tcl", "warning": [], "dangerous": []},
                        {
                            "filepath": "warning.tcl",
                            "warning": [
                                "Unquoted expr at `1` in `expr 1 + 1`",
                                "Unquoted expr at `+` in `expr 1 + 1`",
                                "Unquoted expr at `1` in `expr 1 + 1`",
                            ],
                            "dangerous": [],
                        },
                    ]
                }
            },
        },
    },
    summary="Scan one or multiple files",
)
async def scanfiles(file: list[UploadFile]):
    """
    Submit one or multiple files in multipart/form-data. Returns a JSON object with results for each file.

    Example usage:

    ```shell
    $ curl -s http://localhost/scanfiles/ -F 'file=@tests/basic/warning.tcl' -F 'file=@tests/basic/ok.tcl'
    [
        {"filepath":"ok.tcl","warning":[],"dangerous":[]},
        {"filepath":"warning.tcl",
         "warning":["Unquoted expr at `1` in `expr 1 + 1`","Unquoted expr at `+` in `expr 1 + 1`","Unquoted expr at `1` in `expr 1 + 1`"],
         "dangerous":[]
        }
    ]
    ```
    """
    results: list = []
    for _file in sorted(
        file, reverse=False, key=lambda upload_file: upload_file.filename
    ):
        data = await _file.read()
        async with WriteTmpfile(decode(data)) as tmpfile:
            _result = await irulescan(tmpfile.filename)
            results.append(
                Result(
                    filepath=_file.filename,
                    warning=_result[0].get("warning", []) if _result else [],
                    dangerous=_result[0].get("dangerous", []) if _result else [],
                )
            )

    return results


SCAN_EXAMPLES = {
    "dangerous": """when HTTP_REQUEST {
    set one 1
    expr 1 + $one
}""",
    "warning": """when HTTP_REQUEST {
    set number {3}
    switch $number {
        {1} {}
        {2} {}
    }
}""",
    "ok": """when HTTP_REQUEST priority 500 {
    set number {3}
    switch -- $number {
        {1} {}
        {2} {}
    }
}""",
}


@app.post(
    "/scan/",
    tags=["irulescan"],
    responses={
        200: {
            "description": "Returns the irulescan result.",
            "content": {
                "application/json": {
                    "example": {
                        "warning": [
                            "Unquoted expr at `1` in `expr 1 + $one`",
                            "Unquoted expr at `+` in `expr 1 + $one`",
                        ],
                        "dangerous": [
                            "Dangerous unquoted expr at `$one` in `expr 1 + $one`"
                        ],
                    }
                }
            },
        }
    },
    summary="Scan POST data",
)
async def scan(
    source_code: str = Body(
        media_type="application/json",
        examples={
            "dangerous": {
                "summary": "Dangerous unqouted expression",
                "description": "A dangerous unqouted expression potentially permits code injection",
                "value": SCAN_EXAMPLES["dangerous"],
            },
            "warning": {
                "summary": "Missing options terminator",
                "description": "Missing options terminator permits argument injection",
                "value": SCAN_EXAMPLES["warning"],
            },
            "ok": {
                "summary": "No findings",
                "description": "Code seems fine, no findings to report.",
                "value": SCAN_EXAMPLES["ok"],
            },
        },
    ),
):
    """
    Accepts plaintext content and treats it as a file. Returns the irulescan results as JSON.

    Example usage:

    ```shell
    $ curl -s http://localhost/scan/ --data-binary @tests/basic/dangerous.tcl
    {
        "warning": [
            "Unquoted expr at `1` in `expr 1 + $one`",
            "Unquoted expr at `+` in `expr 1 + $one`"
        ],
        "dangerous": ["Dangerous unquoted expr at `$one` in `expr 1 + $one`"]
    }
    ```
    """
    async with WriteTmpfile(source_code) as tmpfile:
        result = await irulescan(tmpfile.filename)
        result = result[0]  # only one file is scanned, remove enclosing list
        result.pop("filepath")  # remove filepath from result
        return result
