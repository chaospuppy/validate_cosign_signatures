#!/usr/bin/env python3
import requests
import urllib
import requests
import os
import re
from pathlib import Path
from modules.harbor import HarborProject
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.utils import logger
from time import strptime, mktime
from requests import Session

log = logger.setup("validate")

publickey = "cosign.pub"
COSIGN_TAG_REGEX = re.compile("^(sha[0-9]+)-([a-z0-9]+)\.(sig|att|sbom)$")
COSIGN_SIGNATURE_START_TIME = int(mktime(strptime("2022-03-18T09:48:00", "%Y-%m-%dT%H:%M:%S")))

harbor_session = Session()
harbor_session.auth = (os.environ["HARBOR_UN"], os.environ["HARBOR_PW"])

ironbank = HarborProject(harbor_session, name="ironbank")
ironbank.get_project_repository(all=True)

def artifact_is_cosign_accessory(artifact):
    for tag in artifact.tags:
      tag = tag["name"]
      if m := re.match(COSIGN_TAG_REGEX, tag):
          return True
    return False


repository_count = len(ironbank.repositories)
for i, repository in enumerate(ironbank.repositories):
    log.info("Validating images in repository %s, [%i/%i]", repository.name, i, repository_count)
    repository.get_repository_artifact(all=True)
    for artifact in repository.artifacts:
        push_time = int(mktime(strptime(artifact.push_time.split(".")[0], '%Y-%m-%dT%H:%M:%S')))
        if artifact.tags and not artifact_is_cosign_accessory(artifact) and push_time > COSIGN_SIGNATURE_START_TIME:
            image = Image(
                    registry=ironbank.registry,
                    name=f"{ironbank.name}/{repository.name}",
                    digest=artifact.digest,
                    )
            try:
                Cosign.verify(image, publickey)
            except GenericSubprocessError:
                log.info(f"SIGNATURE VALIDATION FAILURE: {image}, pushed at {artifact.push_time} has not been signed!!")
