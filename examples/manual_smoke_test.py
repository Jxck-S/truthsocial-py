from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_credentials import PASSWORD, USERNAME
from truthpy import Status, TruthSocialApp, TruthSocialError

IMAGE_PATH = Path(__file__).with_name("truthpy-test.png")

# Truth Social currently accepts public visibility for these posting calls.
VISIBILITY = "public"


def validate_setup() -> None:
    credentials = {
        "USERNAME": USERNAME,
        "PASSWORD": PASSWORD,
    }
    missing = [
        name
        for name, value in credentials.items()
        if not value or value.startswith("PUT_YOUR_")
    ]
    if missing:
        names = ", ".join(missing)
        raise SystemExit(
            "Fill in these values in examples/local_credentials.py first: "
            f"{names}"
        )

    if not IMAGE_PATH.is_file():
        raise SystemExit(
            f"Missing {IMAGE_PATH}. Run: "
            "python examples/generate_test_image.py"
        )
    if not IMAGE_PATH.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise SystemExit(f"{IMAGE_PATH} is not a valid PNG file")


def print_status(label: str, status: Status) -> None:
    print(f"{label}: id={status.id}")
    if status.url:
        print(f"  {status.url}")


def main() -> int:
    validate_setup()

    print("This live test creates three real Truth Social posts:")
    print(f"  1. A text post ({VISIBILITY})")
    print(f"  2. A reply to that post ({VISIBILITY})")
    print(f"  3. A post containing {IMAGE_PATH.name} ({VISIBILITY})")
    print("The script does not delete them afterward.")
    print("WARNING: all three posts will be publicly visible.")
    if input("Type POST PUBLIC to continue: ").strip() != "POST PUBLIC":
        print("Cancelled; nothing was posted.")
        return 0

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    try:
        print("Creating an app from the current web-app OAuth credentials...")
        app = TruthSocialApp.from_web()
        with app.login(USERNAME, PASSWORD) as client:
            account = client.verify_credentials()
            print(f"Authenticated as @{account.acct}")

            text_post = client.post_status(
                f"truthpy live test {run_id}: text post",
                visibility=VISIBILITY,
                idempotency_key=f"truthpy-{run_id}-text",
            )
            print_status("Text post", text_post)

            reply = client.reply(
                text_post,
                f"truthpy live test {run_id}: reply",
                visibility=VISIBILITY,
                idempotency_key=f"truthpy-{run_id}-reply",
            )
            print_status("Reply", reply)

            image_post = client.post_status(
                f"truthpy live test {run_id}: image post",
                media_files=[IMAGE_PATH],
                visibility=VISIBILITY,
                idempotency_key=f"truthpy-{run_id}-image",
            )
            print_status("Image post", image_post)
    except TruthSocialError as exc:
        print(f"Truth Social request failed: {exc}", file=sys.stderr)
        return 1

    print("Live smoke test completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
