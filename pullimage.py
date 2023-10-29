#!/usr/bin/env python3
import sys
import requests
import json
import urllib3 # urllib3 is a transitive dependency of requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DOCKER_HUB_REGISTRY = 'registry.hub.docker.com'

def get_registry_from_image(image: str):
	'''
	ubuntu:latest -> no registry
	ghcr.io/namespace/image:latest -> ghcr.io
	localhost:5000/library/alpine -> localhost:5000

	returns string of registry domain or None
	'''
	elements_slash_separated = image.split('/')
	if len(elements_slash_separated) <= 2:
		return None
	return elements_slash_separated[0]

def get_ref_tag_from_image(image: str):
	if len(image.split(":")) <= 1:
		return None
	return image.split(":")[1]

def get_repo_from_image(image: str):
	'''
	localhost:5000/library/alpine -> library/alpine
	ubuntu:latest -> library/ubuntu
	'''
	if get_registry_from_image(image) == None:
		if '/' not in image:
			return 'library/' + image.split(":")[0]
		else:
			return image.split(":")[0]
	else:
		if '/' not in image:
			return 'library/' + image.split(":")[0]
		return '/'.join(image.split("/")[1:]).split(":")[0]


def get_manifest(image: str, auth=None):
	# auth: basic auth tuple, optional

	# nice article explaining it: https://www.redhat.com/architect/pull-container-image
	# GET /v2/<repo>/<image>/manifests/<tag>
	# example:
	# GET /v2/library/postgres/manifests/14

	# list all images in a registry (wont work for dockerhub..?): curl http://somehost/v2/_catalog
	# GET /v2/<repository>/tags/list for getting all tags for that repo

	registry = get_registry_from_image(image)
	if registry == None:
		print(f"assuming {DOCKER_HUB_REGISTRY} as registry")
		registry = DOCKER_HUB_REGISTRY # assume docker hub
	print('registry:', registry)

	tag = get_ref_tag_from_image(image)
	if tag == None:
		print("assuming latest as tag since none specified")
		tag = "latest"
	print('tag:', tag)

	repo = get_repo_from_image(image)
	print('repo:', repo)

	protocol_succeed = None
	auth_type = "Bearer" # default, could be something else
	auth_token = None
	www_authenticate = None

	# check if auth is required
	try: # try https first
		r = requests.get(f'https://{registry}/v2/', verify=False)
		protocol_succeed = 'https'
		if r.status_code == 401:
			www_authenticate = r.headers['Www-Authenticate']
		elif r.status_code != 200:
			print("bad status code on registry:", r.status_code, r.text)


	except requests.exceptions.SSLError as e:
		print("error using https url, using http")
		protocol_succeed = 'http'
		r = requests.get(f'http://{registry}/v2/')
		if r.status_code == 401:
			www_authenticate = r.headers['Www-Authenticate']
		elif r.status_code != 200:
			print("bad status code on registry:", r.status_code, r.text)

	if www_authenticate:
		# e.g. Bearer
		auth_type =  www_authenticate.split()[0]
		auth_endpoint = www_authenticate.split()[1].split('realm="')[1].split('"')[0]
		auth_service = www_authenticate.split()[1].split('service="')[1].split('"')[0]
		r = requests.get(f'{auth_endpoint}?scope=repository:{repo}:pull&service={auth_service}', verify=False)
		if r.status_code != 200:
			print("could not get auth token from registry:", r.status_code, r.text)
			exit(1)
		try:
			# WTF, why is there ambiguity here!!!?? bloody OAuth
			# pick one damn it
			if "token" in r.json(): 
				auth_token = r.json()['token']
			elif "auth_token" in r.json():
				auth_token = r.json()['access_token']

		except KeyError as e:
			print("failed to get access_token:", r.status_code, r.text)


	manifest = None
	

	# try https first
	try:
		url = f"https://{registry}/v2/{repo}/manifests/{tag}"
		print("getting manifest url:", url)
		if auth_token:
			r = requests.get(url, timeout=3, headers={"Authorization":f"{auth_type} {auth_token}"}, verify=False) # verify=False if you need self signed certs
		else:
			r = requests.get(url, timeout=3)

		protocol_succeed = "https"
		manifest = r.json()


	except requests.exceptions.SSLError as e:
		
		print("trying http next")
		url =  f"http://{registry}/v2/{repo}/manifests/{tag}"
		print("getting manifest url:", url)
		# assume no auth here, try auth later
		r = requests.get(url, timeout=3)
		protocol_succeed = "http"
		manifest = r.json()


	if protocol_succeed == None:
		print("Fatal: failed getting manifest")
		exit(1)

	if "manifests" in manifest: # manifest list
		# select the first one for now, it's most likely amd64
		print("manifest list detected, selecting first one")
		print("platform:", manifest["manifests"][0]["platform"])
		digest = manifest["manifests"][0]["digest"]
		media_type =  manifest["manifests"][0]["mediaType"]
		url = f"{protocol_succeed}://{registry}/v2/{repo}/manifests/{digest}"
		headers = {"Accept":media_type}
		if auth_token:
			headers["Authorization"] = f"{auth_type} {auth_token}"

		print("media type:", media_type)
		print("chosen manifest url:", url)
		r = requests.get(url, timeout=3, headers=headers, verify=False) # verify=False if you need self signed certs
		manifest = r.json()


	print(json.dumps(manifest, indent=2))
	return manifest





def main():
	if len(sys.argv) < 2:
		print("Usage: %s <image>" %sys.argv[0])
		print("Examples:")
		print("%s alpine:latest")
		print("%s localhost:5000/ubuntu:latest")
		print("%s gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine")
	image = sys.argv[1]
	manifest = get_manifest(image)
	# parse manifest
	# for schema v2, config, layers
	# for schama v1, fsLayers, history
	schema_version = manifest["schemaVersion"]


if __name__ == '__main__':
	main()
