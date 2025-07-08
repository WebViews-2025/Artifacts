import os
import hashlib
import shutil
import sys
import pandas as pd
import logging
from multiprocessing import Pool, cpu_count, Manager

logging.basicConfig(
    filename="webview_permissions.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

logging.getLogger().addHandler(stdout_handler)


class WebViewPermissionChecker:
    def __init__(self, lock):
        self.base_store_path = ""
        self.base_results_file = "webview_permissions_analysis.csv"
        self.decompile_apk_temp_dir = ""
        self.lock = lock

    def decompile_apk(self, app_id, apk_content):
        logging.info("Decompiling app: " + apk_content)

        apk_content_dir = apk_content.split("/")[-1]
        renamed_filename = apk_content_dir.rsplit(".", 1)
        apk_content_dir = "_".join(renamed_filename)

        apk_file_path = os.path.abspath(apk_content)
        decompile_temp_dir = os.path.abspath(
            os.path.join(self.decompile_apk_temp_dir, app_id, apk_content_dir)
        )
        os.makedirs(os.path.dirname(decompile_temp_dir), exist_ok=True)
        logging.info("Decompiling app in: " + decompile_temp_dir)
        os.system(
            f'java -jar apktool_2.9.3.jar d "{apk_file_path}" -o "{decompile_temp_dir}" -f'
        )
        if not os.path.exists(decompile_temp_dir):
            raise Exception("Decompile failed: " + app_id)
        logging.info("Decompiled app in: " + decompile_temp_dir)
        return decompile_temp_dir

    def search_string_in_files(self, directory):
        matches = []
        search_strings = [
            "onGeolocationPermissionsShowPrompt",
            "Landroid/webkit/GeolocationPermissions$Callback;",
            "onPermissionRequest",
            "Landroid/webkit/PermissionRequest;",
        ]

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        if any(
                            search_string in content for search_string in search_strings
                        ):
                            matches.append(file_path)
                            logging.info(f"Found matching string in: {file_path}")

        logging.info(f"Found {len(matches)} matching files in: {directory}")
        return matches

    @staticmethod
    def string_to_hash(input_string):
        input_bytes = input_string.encode("utf-8")
        hash_object = hashlib.sha256(input_bytes)
        hash_hex = hash_object.hexdigest()
        return hash_hex

    def save_smali_code(self, app_id, file_paths, apk_content):
        if len(file_paths) == 0:
            logging.info("No matching strings found for: " + apk_content)
            return
        apk_content_dir = apk_content.split("/")[-1]
        renamed_filename = apk_content_dir.rsplit(".", 1)
        apk_content_dir = "_".join(renamed_filename)

        smali_base_store_path = os.path.abspath(
            os.path.join(self.base_store_path, app_id, apk_content_dir)
        )
        os.makedirs(smali_base_store_path, exist_ok=True)
        for path in file_paths:
            smali_base_path = os.path.abspath(os.path.join(self.decompile_apk_temp_dir))
            smali_store_name = path.replace(smali_base_path + "/", "")
            smali_store_path = os.path.abspath(
                os.path.join(
                    smali_base_store_path,
                    self.string_to_hash(smali_store_name) + ".smali",
                )
            )
            with open(path, "r", encoding="utf-8") as f:
                smali_code = f.read()
                with open(smali_store_path, "w") as smali_f:
                    smali_f.write(smali_store_name)
                    smali_f.write("\n\n")
                    smali_f.write(smali_code)
        logging.info("Stored smali code: " + smali_base_store_path)

    def webview_id_pipeline(self, app):
        app_id, apk_path, results_path, webview_present, apktool_analysed = app
        logging.info("Processing app: " + app_id)
        try:
            apk_path = os.path.abspath(os.path.join(apk_path, "base.apk"))
            decompiled_dir = self.decompile_apk(app_id, apk_path)
            logging.info("Decompiled app: " + apk_path)
            matches = self.search_string_in_files(decompiled_dir)
            self.save_smali_code(app_id, matches, apk_path)
            has_webviews = len(matches) > 0
            self.complete_analysis(app_id, has_webviews)
        except Exception as e:
            logging.error(f"Error analysing app: {app_id}", exc_info=e)
        finally:
            self.delete_decompiled_apk(app_id)
            logging.info(f"Analysis complete for: {app_id}, {apk_path}")

    def delete_decompiled_apk(self, app_id):
        decompile_temp_dir = os.path.abspath(
            os.path.join(self.decompile_apk_temp_dir, app_id)
        )
        if os.path.exists(decompile_temp_dir):
            logging.info(f"Deleting decompiled apk: {app_id} " + decompile_temp_dir)
            shutil.rmtree(decompile_temp_dir)
            logging.info(f"Deleted decompiled apk: {app_id} " + decompile_temp_dir)

    def main(self):
        logging.info("Starting analysis")
        apps_list = self.setup_analysis()
        pool_size = min(10, cpu_count())
        with Pool(pool_size) as p:
            p.map(self.webview_id_pipeline, apps_list)
        logging.info("All apps processed")

    def setup_analysis(self):
        results_df = pd.read_csv(self.base_results_file)
        results_df["apktool_analysed"] = results_df["apktool_analysed"].astype(bool)
        return (
            results_df[results_df["apktool_analysed"] == False]
            .reset_index(drop=True)
            .to_records(index=False)
        )

    def complete_analysis(self, app_id, is_webview_present):
        with self.lock:
            store_path = os.path.join(self.base_store_path, app_id)
            results_df = pd.read_csv(self.base_results_file)
            results_df.loc[results_df["app_id"] == app_id, "apktool_analysed"] = True
            results_df.loc[results_df["app_id"] == app_id, "results_path"] = store_path
            results_df.loc[
                results_df["app_id"] == app_id, "webview_permissions"
            ] = is_webview_present
            results_df.to_csv(self.base_results_file, index=False)
            logging.info("Results stored for app: " + app_id)


if __name__ == "__main__":
    with Manager() as manager:
        lock = manager.Lock()
        checker = WebViewPermissionChecker(lock)
        checker.main()
