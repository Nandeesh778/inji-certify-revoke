FROM eclipse-temurin:21-jre

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG spring_config_label

# can be passed during Docker build as build time environment for spring profiles active
ARG active_profile

# can be passed during Docker build as build time environment for config server URL
ARG spring_config_url

# can be passed during Docker build as build time environment for hsm client zip file path
ARG hsm_client_zip_path

# environment variable to pass hsm client zip file path, at docker runtime
ENV hsm_zip_file_path=${hsm_client_zip_path}

# environment variable to pass active profile such as DEV, QA etc at docker runtime
ENV active_profile_env=${active_profile}

# environment variable to pass github branch to pickup configuration from, at docker runtime
ENV spring_config_label_env=${spring_config_label}

# environment variable to pass spring configuration url, at docker runtime
ENV spring_config_url_env=${spring_config_url}

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user=mosip

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_group=mosip

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_uid=1001

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_gid=1001


ARG hsm_local_dir=hsm-client

ENV hsm_local_dir_name=${hsm_local_dir}

# install packages and create user
RUN apt-get -y update \
&& apt-get install -y unzip sudo\
&& groupadd -g ${container_user_gid} ${container_user_group} \
&& useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user} \
&& usermod -aG sudo ${container_user} \
&& echo "%sudo ALL=(ALL) NOPASSWD:/home/${container_user}/${hsm_local_dir}/install.sh" >> /etc/sudoers \
&& rm -rf /var/cache/apt/archives /var/lib/apt/lists/* \
&& wget "https://raw.githubusercontent.com/mosip/artifactory-ref-impl/v1.3.0-beta.1/artifacts/src/hsm/client.zip" -O /home/${container_user}/client.zip

# set working directory for the user
WORKDIR /home/${container_user}

ENV work_dir=/home/${container_user}

ARG loader_path=${work_dir}/additional_jars/

RUN mkdir -p ${loader_path}

ENV loader_path_env=${loader_path}

ADD configure_start.sh configure_start.sh

RUN chmod +x configure_start.sh

RUN chmod a-w /home/${container_user}/configure_start.sh

COPY ./target/certify-service-*.jar certify-service.jar

# change permissions of file inside working dir
RUN chown -R ${container_user}:${container_user} /home/${container_user}

# select container user for all tasks
USER ${container_user_uid}:${container_user_gid}

EXPOSE 8090
EXPOSE 9010

ENTRYPOINT [ "./configure_start.sh" ]

CMD ["java", "-jar", "-Dloader.path=${loader_path_env}", "-Dspring.cloud.config.label=${spring_config_label_env}", "-Dspring.profiles.active=${active_profile_env}", "-Dspring.cloud.config.uri=${spring_config_url_env}", "certify-service.jar"]

