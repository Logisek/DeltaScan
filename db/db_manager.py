from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    IntegerField,
    DateTimeField,
    PrimaryKeyField,
    ForeignKeyField,
)
import datetime

db = SqliteDatabase("deltascan.db")


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
    host = CharField()
    hostOS = CharField()


class Ports(BaseModel):
    scanResultID = ForeignKeyField(ScanResults, to_field="scanResultId")
    port = IntegerField()
    service = CharField()
    state = CharField()


def initializeDatabase():
    db.connect()
    db.create_tables([Profiles, ScanList, ScanResults], safe=True)


def setScanResults(host, port, service, state, hostOS):
    ScanResults.create(
        host=host, port=port, service=service, state=state, hostOS=hostOS
    )

    return None


def getScanResults(id):
    response = list(ScanResults.select().where(ScanResults.scanId == id))

    return response


def setProfiles(name):
    Profiles.create(profileName=name)

    return None


def getProfiles(name):
    profile = Profiles.get(Profiles.profileName == name)

    return profile


def setScanList(profile, arguments):
    ScanList.create(profileName=profile, scanArguments=arguments)

    return None


def getScanList(profile):
    scanList = ScanList.get(ScanList.profileName == profile)

    return scanList


def setPort(scanResultId, port, service, state):
    Ports.create(scanResultId=scanResultId, port=port, service=service, state=state)

    return None


def getPort(scanResultId):
    ports = Ports.get(Ports.scanResultID == scanResultId)

    return ports
