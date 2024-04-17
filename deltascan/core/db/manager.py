from sqlite3 import DatabaseError
from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    DateTimeField,
    AutoField,
    ForeignKeyField,
    DoesNotExist,
    IntegrityError,
    OperationalError
)
import os
import datetime
import logging
from deltascan.core.config import LOG_CONF

from deltascan.core.exceptions import (DScanRDBMSEntryNotFound,
                                       DScanRDBMSErrorCreatingEntry,
                                       DScanPermissionDeniedError)
from deltascan.core.config import (DATABASE, APP_DATE_FORMAT)

db = SqliteDatabase(DATABASE)


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
        id (int): The unique identifier for the profile.
        profile_name (str): The name of the profile. If a name is not given, it will be generated automatically.
        arguments (str): The arguments associated with the profile.
        created_at (datetime): The timestamp of when the profile was created.
    """
    id = AutoField()
    profile_name = CharField(unique=True)  # TODO: If a name is not given, generate one
    arguments = CharField()
    created_at = DateTimeField(default=datetime.datetime.now().strftime(APP_DATE_FORMAT))


class Scans(BaseModel):
    """
    Represents a scan in the database.

    Attributes:
        id (int): The unique identifier of the scan.
        uuid (str): The UUID of the scan.
        host (str): The host of the scan.
        host_os (str): The operating system of the host.
        profile (Profiles): The profile associated with the scan.
        custom_command (str): The custom command used for the scan (optional).
        results (str): The results of the scan.
        result_hash (str): The hash of the scan results.
        created_at (datetime): The timestamp when the scan was created.
    """
    id = AutoField()
    uuid = CharField()
    host = CharField()
    host_subnet = CharField()
    host_os = CharField()
    profile = ForeignKeyField(Profiles, field="id", null=False)
    custom_command = CharField(null=True)
    results = CharField()
    result_hash = CharField()
    created_at = DateTimeField(default=datetime.datetime.now().strftime(APP_DATE_FORMAT))


class RDBMS:
    def __init__(self, logger=None):
        """
        Initializes the Manager object.

        Args:
            logger (Logger, optional): The logger object to use for logging. Defaults to None.

        Raises:
            RDBMSException: If there is an error initializing the database.

        """
        self.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        try:
            if db.is_closed():
                db.connect()
                db.create_tables([Profiles, Scans], safe=True)
        except OperationalError as e:
            self.logger.error("Operation not permitted.")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except Exception as e:
            self.logger.error("Error initializing database: " + str(e))
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
        except OperationalError as e:
            self.logger.error("Operation not permitted.")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except Exception as e:
            self.logger.error("Error closing database connection: " + str(e))
            # TODO: raise custom RDBMSException

    def create_port_scan(self,
                         uuid: str,
                         host: str,
                         host_with_subnet: str,
                         host_os: str,
                         profile: str,
                         results: str,
                         results_hash: str,
                         custom_command=None,
                         created_at=None):
        """
        Creates a new port scan entry in the database.

        Args:
            uuid (str): The UUID of the port scan.
            host (str): The host IP address or hostname.
            host_os (str): The operating system of the host.
            profile (str): The name of the profile associated with the scan.
            results (str): The scan results.
            results_hash (str): The hash value of the scan results.
            custom_command (Optional[str]): Custom command used for the scan (default: None).
            created_at (Optional[str]): The creation timestamp of the scan (default: None).

        Returns:
            The newly created port scan entry.

        Raises:
            DScanRDBMSErrorCreatingEntry: If there is an error creating the port scan entry.
        """
        try:
            profile_id = Profiles.select().where(
                Profiles.profile_name == profile).get().id
            new_port_scan = Scans.create(
                uuid=uuid,
                host=host,
                host_subnet=host_with_subnet,
                host_os=host_os,
                profile_id=profile_id,
                custom_command=custom_command,
                results=results,
                result_hash=results_hash,
                created_at=datetime.datetime.now().strftime(APP_DATE_FORMAT) if created_at is None else created_at
            )

            return new_port_scan
        except OperationalError as e:
            self.logger.error("Operation not permitted: create port scan")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except DatabaseError as e:
            self.logger.error("Error setting scan results: " + str(e))
            raise DScanRDBMSErrorCreatingEntry("Error creating profile: " + str(e))

    def create_profile(self, name, arguments):
        """
        Create a new profile with the given name and arguments.

        Args:
            name (str): The name of the profile.
            arguments (str): The arguments for the profile.

        Returns:
            int: The ID of the newly created profile.

        Raises:
            DScanRDBMSErrorCreatingEntry: If there is an error creating the profile.

        """
        try:
            new_profile = Profiles.create(
                profile_name=name,
                arguments=arguments)
            return new_profile.id
        except DatabaseError as e:
            self.logger.error("Error creating profile: " + str(e))
            raise DScanRDBMSErrorCreatingEntry("Error creating profile: " + str(e))
        except OperationalError as e:
            self.logger.error("Operation not permitted: create profile")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except IntegrityError as e:
            self.logger.warning("Profile probably already exists: " + str(e))

    def get_scans(self, uuid, host, limit, profile, from_date=None, to_date=None):
        """
        Retrieve scan results from the database based on the provided parameters.

        Args:
            uuid (str or list): The UUID(s) of the scan(s) to retrieve. If a single UUID is provided as a string,
                                it will be converted to a list.
            host (str): The host for which to retrieve scan results.
            limit (int): The maximum number of scan results to retrieve.
            profile (str): The profile name associated with the scan results.
            from_date (datetime, optional): The starting date for the scan results. Defaults to None.
            to_date (datetime, optional): The ending date for the scan results. Defaults to None.

        Returns:
            list: A list of scan results matching the provided parameters.

        Raises:
            DScanRDBMSEntryNotFound: If no scan results are found for the specified host.

        """
        # provided uuid must be a list or None
        if isinstance(uuid, str):
            uuid = [uuid]
        try:
            fields = [
                Scans.id,
                Scans.uuid,
                Scans.host,
                Scans.host_subnet,
                Scans.results,
                Scans.result_hash,
                Scans.created_at,
                Profiles.profile_name,
                Profiles.arguments
            ]
            return self._get_scans_with_optional_params(Scans, uuid, host, limit, profile, from_date, to_date, fields)
        except OperationalError as e:
            self.logger.error("Operation not permitted: get scans")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except DoesNotExist:
            self.logger.error(f"No scan results found for host {host}")
            raise DScanRDBMSEntryNotFound(f"No scans results found for host {host}")

    def get_scans_count(self):
        """
        Retrieves the count of scans from the database.

        Returns:
            int: The count of scans.

        Raises:
            DScanRDBMSException: If there is an error retrieving the scan count.
        """
        try:
            return Scans.select().count()
        except OperationalError as e:
            self.logger.error("Operation not permitted: get scan count")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except Exception as e:
            self.logger.error("Error retrieving scan count: " + str(e))
            raise DScanRDBMSEntryNotFound("Error retrieving scan count: " + str(e))

    @staticmethod
    def _get_scans_with_optional_params(rdbms, uuid, host, limit, profile, from_date, to_date, fields):
        """
        Retrieve scans from the database based on optional parameters.

        Args:
            rdbms (RDBMS): The relational database management system object.
            uuid (str): The UUID of the scans to retrieve.
            host (str): The host of the scans to retrieve.
            limit (int): The maximum number of scans to retrieve.
            profile (str): The profile name of the scans to retrieve.
            from_date (str): The start date of the scans to retrieve (in the format 'YYYY-MM-DD').
            to_date (str): The end date of the scans to retrieve (in the format 'YYYY-MM-DD').
            fields (list): The list of fields to retrieve for each scan.

        Returns:
            Query: The query object containing the retrieved scans.

        """
        query = rdbms.select(*fields).join(Profiles)

        if from_date is not None and to_date is not None:
            query = query.where(
                (Scans.created_at >= datetime.datetime.strptime(from_date, APP_DATE_FORMAT)) &
                (Scans.created_at <= datetime.datetime.strptime(to_date, APP_DATE_FORMAT)))
        elif from_date is not None:
            query = query.where(Scans.created_at >= datetime.datetime.strptime(from_date, APP_DATE_FORMAT))
        elif to_date is not None:
            query = query.where(Scans.created_at <= datetime.datetime.strptime(to_date, APP_DATE_FORMAT))

        if limit is not None:
            query = query.limit(limit)

        if profile is not None:
            query = query.where(Profiles.profile_name == profile)

        if uuid is not None:
            query = query.where(Scans.uuid << uuid)

        if host is not None:
            query = query.where((Scans.host_subnet == host) | (Scans.host == host))


        return query.dicts().order_by(Scans.created_at.desc())

    def get_profiles(self, profile_name=None):
        """
        Retrieve profiles from the database.

        Args:
            profile_name (str, optional): The name of the profile to retrieve. If not provided, all profiles will be returned.

        Returns:
            list: A list of profile objects matching the given profile name.

        Raises:
            DScanRDBMSEntryNotFound: If no profile is found with the given profile name.
        """
        try:
            fields = [
                Profiles.id,
                Profiles.profile_name,
                Profiles.arguments,
                Profiles.created_at
            ]
            return self._get_profiles_with_optional_params(Profiles,  profile_name, fields)
        except OperationalError as e:
            self.logger.error("Operation not permitted: get profiles")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except DoesNotExist:
            self.logger.error(f"No profile found with name {profile_name}")
            raise DScanRDBMSEntryNotFound(f"No profile found with name {profile_name}")

    def get_profile(self, name):
        """
        Retrieves a profile from the database based on the given name.

        Args:
            name (str): The name of the profile to retrieve.

        Returns:
            dict: A dictionary representing the retrieved profile.

        Raises:
            DScanRDBMSEntryNotFound: If no profile is found with the given name.
        """
        try:
            profile = Profiles.select().where(
                Profiles.profile_name == name).dicts().get()
            return profile
        except OperationalError as e:
            self.logger.error("Operation not permitted: get profile")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except DoesNotExist:
            self.logger.error(f"No profile found with name {name}")
            raise DScanRDBMSEntryNotFound(f"No profile found with name {name}")

    def get_profiles_count(self):
        """
        Retrieves the count of profiles from the database.

        Returns:
            int: The count of profiles.

        Raises:
            DScanRDBMSException: If there is an error retrieving the profile count.
        """
        try:
            return Profiles.select().count()
        except OperationalError as e:
            self.logger.error("Operation not permitted: profile count")
            raise DScanPermissionDeniedError(f"Permission error: {str(e)}")
        except Exception as e:
            self.logger.error("Error retrieving profile count: " + str(e))
            raise DScanRDBMSEntryNotFound("Error retrieving profile count: " + str(e))

    @staticmethod
    def _get_profiles_with_optional_params(rdbms, profile_name, fields):
        """
        Retrieves profiles from the database based on the given parameters.

        Args:
            rdbms (RDBMS): The RDBMS object used for executing the query.
            profile_name (str): The name of the profile to filter by. If None, all profiles will be returned.
            fields (list): The list of fields to select from the profiles table.

        Returns:
            list: A list of dictionaries representing the selected profiles.
        """
        query = rdbms.select(*fields)
        if profile_name is not None:
            query = query.where(Profiles.profile_name == profile_name)

        return query.dicts()
