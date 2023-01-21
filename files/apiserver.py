"""Simple API server for irulescan"""
import asyncio
import os
import sys
from shlex import quote as shlex_quote
from tempfile import mkstemp

REQUIREMENTS_TXT = """
aiofile
fastapi
python-multipart
uvicorn[standard]
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
    """async context manager to wirte data to a temporary file"""

    def __init__(self, data: str):
        self.__data = data
        self.filename = ""

    async def __aenter__(self):
        fd, tmpfile = mkstemp()
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


async def irulescan(filepath: str):
    """executes irulescan check on the given filepath and returns stdout or throws an HTTPException"""
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

    return stdout.decode()


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
            "description": "Check submitted iRules for potential security issues.",
        },
    ],
    description="[irulescan homepage](https://github.com/simonkowallik/irulescan/)",
    title="irulescan",
    version="1.1.0",
    docs_url="/",
)


class Result(BaseModel):
    filename: str
    output: str


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
                        {
                            "filename": "dangerous.tcl",
                            "output": "WARNING: Unquoted expr at `1` in `expr 1 + $one`\nWARNING: Unquoted expr at `+` in `expr 1 + $one`\nDANGEROUS: Dangerous unquoted expr at `$one` in `expr 1 + $one`\n\n",
                        },
                        {"filename": "ok.tcl", "output": ""},
                        {
                            "filename": "warning.tcl",
                            "output": "WARNING: Unquoted expr at `1` in `expr 1 + 1`\nWARNING: Unquoted expr at `+` in `expr 1 + 1`\nWARNING: Unquoted expr at `1` in `expr 1 + 1`\n\n",
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
      { "filename": "ok.tcl", "output": "" },
      { "filename": "warning.tcl", "output": "WARNING: Unquoted expr at `1` in `expr 1 + 1`\\nWARNING: Unquoted expr at `+` in `expr 1 + 1`\\nWARNING: Unquoted expr at `1` in `expr 1 + 1`\\n\\n" }
    ]
    ```
    """
    results: list = []
    for _file in sorted(
        file, reverse=False, key=lambda upload_file: upload_file.filename
    ):
        data = await _file.read()
        async with WriteTmpfile(decode(data)) as tmpfile:
            results.append(
                Result(
                    filename=_file.filename, output=await irulescan(tmpfile.filename)
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
            "description": "Returns the irulescan result as text/plain.",
            "content": {
                "text/plain": {
                    "example": "WARNING: Unquoted expr at `1` in `expr 1 + $one`\nWARNING: Unquoted expr at `+` in `expr 1 + $one`\nDANGEROUS: Dangerous unquoted expr at `$one` in `expr 1 + $one`\n\n"
                }
            },
        }
    },
    response_class=PlainTextResponse,
    summary="Scan POST data",
)
async def scan(
    source_code: str = Body(
        media_type="text/plain",
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
    )
):
    """
    Accepts plaintext content and treats it as a file. Returns the irulescan results as plaintext.

    Example usage:

    ```shell
    $ curl -s http://localhost/scan/ --data-binary @tests/basic/dangerous.tcl
    WARNING: Unquoted expr at `1` in `expr 1 + $one`
    WARNING: Unquoted expr at `+` in `expr 1 + $one`
    DANGEROUS: Dangerous unquoted expr at `$one` in `expr 1 + $one`

    ```
    """
    async with WriteTmpfile(source_code) as tmpfile:
        return await irulescan(tmpfile.filename)
