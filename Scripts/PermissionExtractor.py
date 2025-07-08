import os
import subprocess
import json
import logging
from multiprocessing import Pool, cpu_count, Manager
import sys
import re
import pandas as pd

# Logging configuration
logging.basicConfig(
    filename="webview_permissions_extractor.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

logging.getLogger().addHandler(stdout_handler)


class PermissionExtractor:
    def __init__(self, lock):
        self.apk_directory = ""
        self.permissions_store_path = ""
        self.results_file = "webview_permissions_extractor.csv"
        self.lock = lock

    def check_aapt2(self):
        try:
            subprocess.run(
                ["aapt2", "version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logging.info("aapt2 tool is available.")
        except subprocess.CalledProcessError:
            logging.error(
                "aapt2 tool is not available. Please ensure it is installed and in your PATH."
            )
            raise EnvironmentError(
                "aapt2 tool is not available. Please ensure it is installed and in your PATH."
            )

    def extract_permissions(self, app):
        app_id, apk_path, permissions_path, aapt2_analysed = app
        if aapt2_analysed:
            logging.info(f"Skipping already analysed app: {app_id}")
            return

        try:
            result = subprocess.run(
                [
                    "aapt",
                    "dump",
                    "permissions",
                    os.path.abspath(os.path.join(apk_path, "base.apk")),
                ],
                capture_output=True,
                text=True,
            )
            lines = result.stdout.splitlines()

            logging.info(f"aapt2 stdout: {result.stdout}")
            logging.info(f"aapt2 stderr: {result.stderr}")

            package_name_pattern = re.compile(r"package:\s+(\S+)")
            permission_pattern = re.compile(r"uses-permission:\s+name='(\S+)'")

            app_id = None
            permissions = []

            for line in lines:
                package_match = package_name_pattern.match(line)
                if package_match:
                    app_id = package_match.group(1)
                permission_match = permission_pattern.match(line)
                if permission_match:
                    permissions.append(permission_match.group(1))

            if app_id:
                output_data = {"app_id": app_id, "permissions": permissions}
                output_filename = f"{app_id}.json"
                output_path = os.path.join(self.permissions_store_path, output_filename)

                with open(output_path, "w") as json_file:
                    json.dump(output_data, json_file, indent=4)

                logging.info(f"Permissions extracted and saved for app: {app_id}")
                self.complete_analysis(app_id, output_path)

        except Exception as e:
            logging.error(
                f"Error extracting permissions for APK: {apk_path}", exc_info=e
            )

    def process_apk_files(self, apps_list):
        pool_size = min(40, cpu_count())
        with Pool(pool_size) as pool:
            pool.map(self.extract_permissions, apps_list)

    def setup_analysis(self):
        results_df = pd.read_csv(self.results_file)
        results_df["aapt2_analysed"] = results_df["aapt2_analysed"].astype(bool)
        return (
            results_df[results_df["aapt2_analysed"] == False]
            .reset_index(drop=True)
            .to_records(index=False)
        )

    def complete_analysis(self, app_id, permissions_path):
        with self.lock:
            results_df = pd.read_csv(self.results_file)
            results_df.loc[results_df["app_id"] == app_id, "aapt2_analysed"] = True
            results_df.loc[
                results_df["app_id"] == app_id, "permissions_path"
            ] = permissions_path
            results_df.to_csv(self.results_file, index=False)
            logging.info(f"Results stored for app: {app_id}")

    def main(self):
        logging.info("Starting the permission extraction process for APK files.")
        apps_list = self.setup_analysis()
        self.process_apk_files(apps_list)
        logging.info("All APK files processed.")


if __name__ == "__main__":
    with Manager() as manager:
        lock = manager.Lock()
        extractor = PermissionExtractor(lock)
        extractor.main()
