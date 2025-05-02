import configLoader
import os


class CdaConfig(configLoader.StrictBaseModel):
    token_user: str = ""
    token: str = "" # taken from https://console-openshift-console.apps.ci.l2s4.p1.openshiftapps.com
    credentials: str = os.path.join(os.environ["HOME"], ".config/gspread/credentials.json")
    state_file_path: str = os.path.join(os.environ["HOME"], ".config/cda/state")


def main() -> None:
    configLoader.load("cda-config.yaml", CdaConfig)


if __name__ == "__main__":
    main()
