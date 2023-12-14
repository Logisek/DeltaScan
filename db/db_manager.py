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
    JOIN,
)
import datetime
import logging
import pprint

db = SqliteDatabase("deltascan.db")
logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class BaseModel(Model):
    """
    Base model class for database models.
    """

    class Meta:
        database = db


class Profiles(BaseModel):
    """
    Represents a profile in the database.

    Attributes:
        id (int): The unique identifier of the profile.
        profileName (str): The name of the profile. If a name is not given, it will be generated.
        creationDate (datetime): The date and time when the profile was created.
    """

    id = PrimaryKeyField()
    profileName = CharField(unique=True)  # TODO: If a name is not given, generate one
    creationDate = DateTimeField(default=datetime.datetime.now)


class ScanList(BaseModel):
    """
    Represents a scan list entry.

    Attributes:
        id (int): The primary key field for the scan list entry.
        profileName (str): The foreign key field referencing the profile name.
        scanArguments (str): The scan arguments for the entry.
        creationDate (datetime): The creation date of the entry.
    """

    id = PrimaryKeyField()
    profileName = ForeignKeyField(Profiles, to_field="profileName")
    scanArguments = CharField()
    creationDate = DateTimeField(default=datetime.datetime.now)


class ScanResults(BaseModel):
    """
    Represents the results of a scan.

    Attributes:
        scanResultId (int): The ID of the scan result.
        scanId (int): The ID of the associated scan.
        timestamp (datetime): The timestamp of when the scan result was created.
    """

    scanResultId = PrimaryKeyField()
    scanId = ForeignKeyField(ScanList, to_field="id")
    timestamp = DateTimeField(default=datetime.datetime.now)


class Hosts(BaseModel):
    """
    Represents a host in the database.

    Attributes:
        scanResultId (ForeignKeyField): The foreign key to the ScanResults table.
        host (CharField): The host name.
        state (BooleanField): The state of the host.
        hostOS (CharField): The operating system of the host.
    """

    scanResultId = ForeignKeyField(ScanResults, to_field="scanResultId")
    host = CharField(unique=True)
    state = BooleanField(default=False)
    hostOS = CharField()


class Ports(BaseModel):
    """
    Represents a port entry in the database.

    Attributes:
        hostId (ForeignKeyField): The foreign key referencing the scanResultId of the Hosts table.
        port (IntegerField): The port number.
        service (CharField): The service associated with the port.
        product (CharField): The product associated with the port.
        state (CharField): The state of the port, which can be 'open', 'closed', or 'filtered'.
    """

    hostId = ForeignKeyField(Hosts, to_field="scanResultId")
    port = IntegerField()
    service = CharField()
    product = CharField()
    state = CharField(
        choices=[("open", "open"), ("closed", "closed"), ("filtered", "filtered")]
    )


def initializeDatabase():
    """
    Initializes the database by connecting to it and creating necessary tables.

    Raises:
        Exception: If an error occurs while initializing the database.

    """
    try:
        if db.is_closed():
            db.connect()
            db.create_tables([Profiles, ScanList, Hosts, ScanResults, Ports], safe=True)

    except Exception as e:
        logging.error("Error initializing database: " + str(e))
        print("An error as occurred, check error.log")


def setScanResults(scanId, host, hostOS, ports, hostState):
    """
    Sets the scan results for a given scan.

    Args:
        scanId (int): The ID of the scan.
        host (str): The host IP address.
        hostOS (str): The operating system of the host.
        ports (list): A list of dictionaries containing port information.
        hostState (str): The state of the host (up or down).

    Returns:
        None
    """
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
    """
    Retrieve scan results for a given scan ID.

    Args:
        id (int): The ID of the scan.

    Returns:
        list: A list of dictionaries representing the scan results. Each dictionary contains
        information about a host, including its IP address, operating system, state, and associated ports.

    Raises:
        DoesNotExist: If no scan results are found with the given ID.

    """
    try:
        scanResults = (
            ScanResults.select()
            .join(Hosts, JOIN.LEFT_OUTER)
            .join(Ports, JOIN.LEFT_OUTER)
            .where(ScanResults.scanId == id)
        )

        # Inefficient, but it works. Will optimize.
        scanResultsList = []
        hosts_seen = {}
        for scan in scanResults:
            for host in scan.hosts_set:
                if host.host not in hosts_seen:
                    hosts_seen[host.host] = {
                        "host": host.host,
                        "os": host.hostOS,
                        "state": host.state,
                        "ports": [],
                    }
                    scanResultsList.append(hosts_seen[host.host])

                    if host.ports_set is not None:
                        for port in host.ports_set:
                            portDict = {
                                "port": port.port,
                                "service": port.service,
                                "product": port.product,
                                "state": port.state,
                            }
                            hosts_seen[host.host]["ports"].append(portDict)

        return scanResultsList

    except DoesNotExist:
        logging.error(f"No scan results found with id {id}")
        return f"No scan results found with id {id}"


def setProfile(name):
    """
    Sets a profile with the given name.

    Args:
        name (str): The name of the profile to be set.

    Returns:
        None
    """
    try:
        Profiles.create(profileName=name)
    except Exception as e:
        logging.error("Error setting profile: " + str(e))
        return f"Error setting profile: {str(e)}"


def getProfile(name):
    """
    Retrieves a profile by its name.

    Args:
        name (str): The name of the profile to retrieve.

    Returns:
        Profile: The profile object if found, None otherwise.
    """
    try:
        profile = Profiles.get(Profiles.profileName == name)
        return profile
    except DoesNotExist:
        logging.error(f"No profile found with name {name}")


def getProfileList():
    """
    Retrieves a list of profiles from the database.

    Returns:
        list: A list of dictionaries representing the profiles. Each dictionary contains the following keys:
            - id (int): The ID of the profile.
            - profileName (str): The name of the profile.
            - creationDate (str): The creation date of the profile.

        None: If there was an error retrieving the profiles.
    """
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
    """
    Create a new scan list with the given profile and arguments.

    Args:
        profile (str): The name of the profile.
        arguments (list): The scan arguments.

    Returns:
        int: The ID of the created scan list.

    Raises:
        Exception: If there is an error setting the scan list.
    """
    try:
        scanList = ScanList.create(profileName=profile, scanArguments=arguments)

        return scanList.id
    except Exception as e:
        logging.error("Error setting scan list: " + str(e))
        return f"Error setting scan list: {str(e)}"


def getScanList(profile):
    """
    Retrieve a list of scans associated with a given profile.

    Args:
        profile (str): The name of the profile.

    Returns:
        list: A list of dictionaries containing scan details, including id, profileName, scanArguments, and creationDate.

    Raises:
        DoesNotExist: If no scans are found with the given profile.

    """
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
    """
    Retrieve the ports associated with a given host ID.

    Args:
        hostId (int): The ID of the host.

    Returns:
        Ports: The ports associated with the host ID.

    Raises:
        DoesNotExist: If no ports are found with the given host ID.
    """
    try:
        ports = Ports.get(Ports.hostId == hostId)
        return ports
    except DoesNotExist:
        logging.error(f"No ports found with scanResultId {hostId}")
        return f"No ports found with scanResultId {hostId}"
