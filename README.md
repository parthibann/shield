# shield
Openssl is commonly used for creating self-signed SSL certificates or an organizational certificate chain, but it is quite complex to manage them all together, that's where shield excels. 

Enter certificate details in shield UI and download the certificate in just one click, shield retains a copy always in the mongo DB so that you can download them at any time.

**OPERATING SYSTEM PREFERRED:** Ubuntu, Centos

**PYTHON VERSION:** 2.7

**PREREQUISITE:** Mongodb

**INSTALLATION INSTRUCTIONS:**

 1. Download / Clone the repository.
 2. Move inside the repository folder and run the following command “pip install –r requirements.txt”
 3. Update config file with mongo db details “shield.conf”
 4. Start the application by running the “shield” file present in the bin directory (e.g python shield)
 
 **DOCKER:**
 1. INSTALL DOCKER AND DOCKER-COMPOSE, refer official docker installation page for installing docker and docker-compose.
 
 Docker: https://docs.docker.com/install/linux/docker-ce/ubuntu/#set-up-the-repository (ubuntu)
 
 Docker-Compose: https://docs.docker.com/compose/install/#install-compose (ubuntu)
 
 2. After instaling, clone this repository and go inside the project directory and run the command mentioned below.
 

    cd shield

    sudo docker-compose up
 
 3. open browser and load https://localhost:5050

**API DOCUMENT:** Document is added as part of the repository and it is present in the documents directory.

SHIELD UI:
![shield](https://user-images.githubusercontent.com/4667360/43354072-e07a1218-9262-11e8-83f7-70a4d6a0453f.gif)
