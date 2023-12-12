from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    IntegerField,
    DateTimeField,
    PrimaryKeyField,
    ForeignKeyField,
    BooleanField,
    DoesNotExist,
)
import datetime
import logging
import pprint

db = SqliteDatabase("deltascan.db")
logging.basicConfig(filename="error.log", level=logging.WARNING)


class BaseModel(Model):
    class Meta:
        database = db


class Profiles(BaseModel):
    id = PrimaryKeyField()
    profileName = CharField(unique=True)  # If a name is not given, generate one
    creationDate = DateTimeField(default=datetime.datetime.now)


class ScanList(BaseModel):
    id = PrimaryKeyField()
    profileName = ForeignKeyField(Profiles, to_field="profileName")
    scanArguments = CharField()
    creationDate = DateTimeField(default=datetime.datetime.now)


class ScanResults(BaseModel):
    scanResultId = PrimaryKeyField()
    scanId = ForeignKeyField(ScanList, to_field="id")
    timestamp = DateTimeField(default=datetime.datetime.now)


class Hosts(BaseModel):
    scanResultId = ForeignKeyField(ScanResults, to_field="scanResultId")
    host = CharField(unique=True)
    state = BooleanField(default=False)
    hostOS = CharField()


class Ports(BaseModel):
    hostId = ForeignKeyField(Hosts, to_field="scanResultId")
    port = IntegerField()
    service = CharField()
    product = CharField()
    state = CharField(
        choices=[("open", "open"), ("closed", "closed"), ("filtered", "filtered")]
    )


def initializeDatabase():
    try:
        if db.is_closed():
            db.connect()
            db.create_tables([Profiles, ScanList, Hosts, ScanResults, Ports], safe=True)

    except Exception as e:
        logging.error("Error initializing database: " + str(e))
        print("An error as occurred, check error.log")


def setScanResults(scanId, host, hostOS, ports, hostState):
    try:
        if hostState == "up":
            hostState = True
        else:
            hostState = False

        scanResult = ScanResults.create(scanId=scanId)
        scanResultId = scanResult.scanResultId

        hostEntry = Hosts.get_or_create(
            scanResultId=scanResultId, host=host, hostOS=hostOS, state=hostState
        )

        for port in ports:
            Ports.create(
                hostId=scanResultId,
                port=port.get("portid", "unknown"),
                service=port.get("service", "unknown"),
                product=port.get("serviceProduct", "unknown"),
                state=port.get("state", "unknown"),
            )

    except Exception as e:
        logging.error("Error setting scan results: " + str(e))
        return f"Error setting scan results: {str(e)}"


def getScanResults(id):
    try:
        scanResults = (
            ScanResults.select().join(Hosts).join(Ports).where(ScanResults.scanId == id)
        )

        scanResultsList = []
        for scan in scanResults:
            for host in scan.hosts_set:
                scanResultsDict = {
                    "host": host.host,
                    "os": host.hostOS,
                    "state": host.state,
                    "ports": [],
                }
                for port in host.ports_set:
                    portDict = {
                        "port": port.port,
                        "service": port.service,
                        "product": port.product,
                        "state": port.state,
                    }
                    scanResultsDict["ports"].append(portDict)

                scanResultsList.append(scanResultsDict)

        return scanResultsList

    except DoesNotExist:
        logging.error(f"No scan results found with id {id}")
        return f"No scan results found with id {id}"


def setProfile(name):
    try:
        Profiles.create(profileName=name)
    except Exception as e:
        logging.error("Error setting profile: " + str(e))
        return f"Error setting profile: {str(e)}"


def getProfile(name):
    try:
        profile = Profiles.get(Profiles.profileName == name)

        return profile

    except DoesNotExist:
        logging.error(f"No profile found with name {name}")


def getProfileList():
    try:
        profiles = Profiles.select()

        profileList = []
        for profile in profiles:
            profileListDict = {
                "id": profile.id,
                "profileName": profile.profileName,
                "creationDate": profile.creationDate,
            }

            profileList.append(profileListDict)

        return profileList

    except DoesNotExist:
        logging.error(f"Error retrieving profiles")
        return None


def setScanList(profile, arguments):
    try:
        scanList = ScanList.create(profileName=profile, scanArguments=arguments)

        return scanList.id
    except Exception as e:
        logging.error("Error setting scan list: " + str(e))
        return f"Error setting scan list: {str(e)}"


def getScanList(profile):
    try:
        allScanLists = ScanList.select().where(ScanList.profileName == profile)

        scanList = []
        for scan in allScanLists:
            scanListDict = {
                "id": scan.id,
                "profileName": scan.profileName.profileName,
                "scanArguments": scan.scanArguments,
                "creationDate": scan.creationDate,
            }

            scanList.append(scanListDict)

        return scanList

    except DoesNotExist:
        logging.error(f"No scans found with profile {profile}")
        return f"No scans found with profile {profile}"


def getPort(hostId):
    try:
        ports = Ports.get(Ports.hostId == hostId)

        return ports

    except DoesNotExist:
        logging.error(f"No ports found with scanResultId {hostId}")
        return f"No ports found with scanResultId {hostId}"
