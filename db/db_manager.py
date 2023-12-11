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

db = SqliteDatabase("deltascan.db")
logging.basicConfig(filename="error.log", level=logging.DEBUG)


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


class Hosts(BaseModel):
    host = CharField(unique=True)
    state = BooleanField(default=False)
    hostOS = CharField()


class ScanResults(BaseModel):
    scanResultId = PrimaryKeyField()
    scanId = ForeignKeyField(ScanList, to_field="id")
    timestamp = DateTimeField(default=datetime.datetime.now)
    host = ForeignKeyField(Hosts, to_field="host")


class Ports(BaseModel):
    scanResultId = ForeignKeyField(ScanResults, to_field="scanResultId")
    port = IntegerField()
    service = CharField()
    product = CharField()
    state = CharField(
        choices=[("open", "open"), ("closed", "closed"), ("filtered", "filtered")]
    )


def initializeDatabase():
    try:
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

        hostEntry, _created = Hosts.get_or_create(
            host=host, hostOS=hostOS, state=hostState
        )
        scanResults = ScanResults.create(scanId=scanId, host=hostEntry)
        scanResultId = scanResults.scanResultId

        for port in ports:
            Ports.create(
                scanResultId=scanResultId,
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
        response = (
            ScanResults.select().join(Hosts).join(Ports).where(ScanResults.scanId == id)
        )

        return response

    except DoesNotExist:
        logging.error(f"No scan results found with id {id}")
        return f"No scan results found with id {id}"


def setProfiles(name):
    try:
        Profiles.create(profileName=name)
    except Exception as e:
        logging.error("Error setting profile: " + str(e))
        return f"Error setting profile: {str(e)}"


def getProfiles(name):
    try:
        profile = Profiles.get(Profiles.profileName == name)

        return profile

    except DoesNotExist:
        logging.error(f"No profile found with name {name}")
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
        scanList = ScanList.get(ScanList.profileName == profile)

        return scanList

    except DoesNotExist:
        logging.error(f"No scans found with profile {profile}")
        return f"No scans found with profile {profile}"


def getPort(scanResultId):
    try:
        ports = Ports.get(Ports.scanResultId == scanResultId)

        return ports

    except DoesNotExist:
        logging.error(f"No ports found with scanResultId {scanResultId}")
        return f"No ports found with scanResultId {scanResultId}"
