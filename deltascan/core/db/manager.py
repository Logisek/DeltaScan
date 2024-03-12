from sqlite3 import DatabaseError
from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    DateTimeField,
    AutoField,
    ForeignKeyField,
    DoesNotExist,
    IntegrityError
)
import os
import datetime
import logging
from deltascan.core.exceptions import (DScanRDBMSEntryNotFound,
                                       DScanRDBMSErrorCreatingEntry)
from deltascan.core.config import DATABASE

db = SqliteDatabase(DATABASE)

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
    id = AutoField()
    profile_name = CharField(unique=True)  # TODO: If a name is not given, generate one
    arguments = CharField()
    creationDate = DateTimeField(default=datetime.datetime.now)

class PortScans(BaseModel):
    """
    Represents a scan in the database.
    """
    id = AutoField()
    host = CharField()
    host_os = CharField()
    profile = ForeignKeyField(Profiles, field="id", null=False)
    custom_command = CharField(null=True)
    results = CharField()
    result_hash = CharField()
    created_at = DateTimeField(default=datetime.datetime.now)

class RDBMS:
    def __init__(self):
        try:
            if db.is_closed():
                db.connect()
                db.create_tables([Profiles, PortScans], safe=True)

        except Exception as e:
            logging.error("Error initializing database: " + str(e))
            print("An error as occurred, check error.log. Exiting...")
            # TODO: raise custom RDBMSException
            os._exit(1)

    def __del__(self):
        """
        Destructor for the RDBMS class.
        """
        try:
            if not db.is_closed():
                db.close()
        except Exception as e:
            logging.error("Error closing database connection: " + str(e))
            # TODO: raise custom RDBMSException

    def create_port_scan(self,
                        host: str,
                        host_os: str,
                        profile: str,
                        results: str,
                        results_hash: str,
                        custom_command=None):
        """
        Saves the scan results to the database.

        Args:
            host (str): The hostname or IP address of the scanned host.
            hostOS (str): The operating system of the scanned host.
            profile (str): The profile used for the scan.
            custom_command (str): The custom command used for the scan.
            results (list): The list of scan results.

        Returns:
            str: A message indicating the success or failure of saving the scan results.
        """
        try:
            profile_id = Profiles.select().where(
                Profiles.profile_name == profile).get().id
            new_port_scan = PortScans.create(
                host=host,
                host_os=host_os,
                profile_id=profile_id,
                custom_command=custom_command,
                results=results,
                result_hash=results_hash
            )

            return new_port_scan.id
        except DatabaseError as e:
            logging.error("Error setting scan results: " + str(e))
            raise DScanRDBMSErrorCreatingEntry("Error creating profile: " + str(e))

    def create_profile(self, name, arguments):
        """
        Sets a profile with the given name.

        Args:
            name (str): The name of the profile to be set.

        Returns:
            None
        """
        try:
            new_profile = Profiles.create(
                profile_name=name,
                arguments=arguments)
            return new_profile.id
        except DatabaseError as e:
            logging.error("Error creating profile: " + str(e))
            raise DScanRDBMSErrorCreatingEntry("Error creating profile: " + str(e))
        except IntegrityError as e:
            logging.error("Profile not created: " + str(e))

    def get_scans(self, host, limit, profile, created_at=None):
        """
        Retrieve scan results for a specific host.

        Args:
            host (str): The host for which to retrieve scan results.
            limit (int): The maximum number of scan results to retrieve.
            created_at (datetime): The minimum creation date of the scan results.

        Returns:
            list: A list of scan results matching the specified criteria.
        """
        try:
            fields= [   PortScans.id,
                        PortScans.host,
                        PortScans.results,
                        PortScans.result_hash,
                        PortScans.created_at,
                        Profiles.profile_name]
            return self._get_scans_with_optional_params(PortScans,
                                                        host,limit,profile,
                                                        created_at,
                                                        fields)
        except DoesNotExist:
            logging.error(f"No scan results found for host {host}")
            raise DScanRDBMSEntryNotFound(f"No scans results found for host {host}")
    
    @staticmethod
    def _get_scans_with_optional_params(rdbms, host, limit, profile, created_at, fields):
        query = rdbms.select(*fields).join(Profiles)
        if created_at is not None:
            query = query.where(
                PortScans.created_at <= created_at).order_by(PortScans.created_at.desc())

        if limit is not None:
            query = query.limit(limit)

        if profile is not None:
            query = query.where(Profiles.profile_name == profile)

        if host is not None:
            query = query.where(PortScans.host == host)

        return query.dicts()

    def get_profile(self, name):
        """
        Retrieves a profile by its name.

        Args:
            name (str): The name of the profile to retrieve.

        Returns:
            Profile: The profile object if found, None otherwise.
        """
        try:
            profile = Profiles.select().where(
                Profiles.profile_name == name).dicts().get()
            return profile
        except DoesNotExist:
            logging.error(f"No profile found with name {name}")
            raise DScanRDBMSEntryNotFound(f"No profile found with name {name}")

