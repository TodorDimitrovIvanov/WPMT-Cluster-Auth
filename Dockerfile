# Source: https://docs.docker.com/language/python/build-images/
# Source: https://docs.docker.com/develop/develop-images/baseimages/
FROM python:3
# Here we set the workdir that Docker will automatically create
# And use as the default location from here on
WORKDIR /root/app
# Here we copy all files within the workding directory to the image
COPY . .
# Here we install the list of dependecies from the 'requirements.txt' file
RUN pip3 install --no-cache-dir -r requirements.txt
CMD ["python3",  "main.py"]