# Placeholder for model code

from datetime import datetime
from typing import List

from sqlalchemy import create_engine, Column, Integer, Numeric, String, DateTime, \
     ForeignKey, event, select
from sqlalchemy.orm import scoped_session, sessionmaker, backref, relation, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import Table

from depobs.database.schema import NPMSIOScore

import os

DATABASE_URI = os.environ.get('DATABASE_URI', 'postgresql+psycopg2://postgres:postgres@localhost/dependency_observatory')

engine = create_engine(DATABASE_URI,
                       convert_unicode=True)

db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

Model = declarative_base()
View_only = declarative_base()
# Model.query = db_session.query_property()

dependency = Table(
    'package_dependencies', Model.metadata,
    Column('depends_on_id', Integer, ForeignKey('reports.id'), primary_key=True),
    Column('used_by_id', Integer, ForeignKey('reports.id'), primary_key=True)
)

class PackageReport(Model):
    __tablename__ = 'reports'

    id = Column('id', Integer, primary_key=True)

    package = Column(String(200))
    version = Column(String(200))
    release_date = Column(DateTime)
    scoring_date = Column(DateTime)
    top_score = Column(Integer)
    npmsio_score = Column(Numeric)
    directVulnsCritical_score = Column(Integer)
    directVulnsHigh_score = Column(Integer)
    directVulnsMedium_score = Column(Integer)
    directVulnsLow_score = Column(Integer)
    indirectVulnsCritical_score = Column(Integer)
    indirectVulnsHigh_score = Column(Integer)
    indirectVulnsMedium_score = Column(Integer)
    indirectVulnsLow_score = Column(Integer)
    authors = Column(Integer)
    contributors = Column(Integer)
    immediate_deps = Column(Integer)
    all_deps = Column(Integer)

    # this relationship is used for persistence
    dependencies = relationship("PackageReport",
                           secondary=dependency,
                           primaryjoin=id==dependency.c.depends_on_id,
                           secondaryjoin=id==dependency.c.used_by_id,
                           backref="parents"
    )

class PackageLatestReport(View_only):
    __tablename__ = 'latest_reports'

    id = Column('id', Integer, primary_key=True)

    package = Column(String(200))
    version = Column(String(200))
    release_date = Column(DateTime)
    scoring_date = Column(DateTime)
    top_score = Column(Integer)
    npmsio_score = Column(Numeric)
    directVulnsCritical_score = Column(Integer)
    directVulnsHigh_score = Column(Integer)
    directVulnsMedium_score = Column(Integer)
    directVulnsLow_score = Column(Integer)
    indirectVulnsCritical_score = Column(Integer)
    indirectVulnsHigh_score = Column(Integer)
    indirectVulnsMedium_score = Column(Integer)
    indirectVulnsLow_score = Column(Integer)
    authors = Column(Integer)
    contributors = Column(Integer)
    immediate_deps = Column(Integer)
    all_deps = Column(Integer)

    # this relationship is used for persistence
    dependencies = relationship("PackageLatestReport",
                           secondary=dependency,
                           primaryjoin=id==dependency.c.depends_on_id,
                           secondaryjoin=id==dependency.c.used_by_id,
                           backref="parents"
    )

    def json_with_dependencies(self, depth = 1):
        return dict(
            id=self.id,
            package=self.package,
            version=self.version,
            release_date=self.release_date,
            scoring_date=self.scoring_date,
            top_score=self.top_score,
            npmsio_score=self.npmsio_score,
            directVulnsCritical_score=self.directVulnsCritical_score,
            directVulnsHigh_score=self.directVulnsHigh_score,
            directVulnsMedium_score=self.directVulnsMedium_score,
            directVulnsLow_score=self.directVulnsLow_score,
            indirectVulnsCritical_score=self.indirectVulnsCritical_score,
            indirectVulnsHigh_score=self.indirectVulnsHigh_score,
            indirectVulnsMedium_score=self.indirectVulnsMedium_score,
            indirectVulnsLow_score=self.indirectVulnsLow_score,
            authors = self.authors,
            contributors = self.contributors,
            immediate_deps = self.immediate_deps,
            all_deps = self.all_deps,
            dependencies = [rep.json_with_dependencies(depth - 1) for rep in self.dependencies] if depth > 0 else []
        )

    def json_with_parents(self, depth = 1):
        return dict(
            id=self.id,
            package=self.package,
            version=self.version,
            release_date=self.release_date,
            scoring_date=self.scoring_date,
            top_score=self.top_score,
            npmsio_score=self.npms_io_score,
            directVulnsCritical_score=self.directVulnsCritical_score,
            directVulnsHigh_score=self.directVulnsHigh_score,
            directVulnsMedium_score=self.directVulnsMedium_score,
            directVulnsLow_score=self.directVulnsLow_score,
            indirectVulnsCritical_score=self.indirectVulnsCritical_score,
            indirectVulnsHigh_score=self.indirectVulnsHigh_score,
            indirectVulnsMedium_score=self.indirectVulnsMedium_score,
            indirectVulnsLow_score=self.indirectVulnsLow_score,
            authors = self.authors,
            contributors = self.contributors,
            immediate_deps = self.immediate_deps,
            all_deps = self.all_deps,
            parents = [rep.json_with_parents(depth - 1) for rep in self.parents] if depth > 0 else []
        )

def get_package_report(package, version = None):
    if None == version:
        #TODO order-by is hard with semver. Think about splitting out versions
        no_version_query = db_session.query(PackageReport).filter(PackageReport.package==package)
        print("Query is %s" % str(no_version_query))
        for rep in no_version_query:
            return rep
    else:
        for rep in db_session.query(PackageReport).filter(PackageReport.package==package, PackageReport.version==version):
            return rep

def get_npms_io_score(package: str, version: str):
    return db_session.query(NPMSIOScore.score).filter_by(package_name=package, package_version=version)

def get_NPMRegistryEntry(package: str, version: str):
    return db_session.query(NPMRegistryEntry).filter_by(package_name=package, package_version=version)

def get_maintainers_contributors(package: str, version: str):
    return db_session.query(NPMRegistryEntry.maintainers, NPMRegistryEntry.contributors).filter_by(package_name=package, package_version=version)

def get_npm_registry_data(package: str, version: str):
    return db_session.query(NPMRegistryEntry.published_at, NPMRegistryEntry.maintainers, NPMRegistryEntry.contributors).filter_by(package_name=package, package_version=version)

def get_direct_dependencies(package: str, version: str):
    palias = aliased(PackageVersion)
    calias = aliased(PackageVersion)
    return db_session.query(calias.name, calias.version
    ).filter(PackageLink.parent_package_id==palias.id
    ).filter(palias.name==package
    ).filter(palias.version==version
    ).filter(PackageLink.child_package_id==calias.id)

def get_vulnerability_counts(package: str, version: str):
    return db_session.query(Advisory.package_name, PackageVersion.version, Advisory.severity, 
        func.count(Advisory.severity)
    ).filter_by(package_name=package
    ).filter(PackageVersion.version==version
    ).filter(Advisory.package_name==PackageVersion.name
    ).group_by(Advisory.package_name, PackageVersion.version, Advisory.severity)

def get_direct_dependency_reports(package: str, version: str):
    palias = aliased(PackageVersion)
    calias = aliased(PackageVersion)
    return db_session.query(calias.name, calias.version, PackageLatestReport.scoring_date, PackageLatestReport.top_score, PackageLatestReport.all_deps,
        PackageLatestReport.directVulnsCritical_score, PackageLatestReport.directVulnsHigh_score, PackageLatestReport.directVulnsMedium_score, PackageLatestReport.directVulnsLow_score,
        PackageLatestReport.indirectVulnsCritical_score, PackageLatestReport.indirectVulnsHigh_score, PackageLatestReport.indirectVulnsMedium_score, PackageLatestReport.indirectVulnsLow_score
    ).filter(PackageLink.parent_package_id==palias.id
    ).filter(palias.name==package
    ).filter(palias.version==version
    ).filter(PackageLink.child_package_id==calias.id
    ).filter(PackageLatestReport.package==calias.name
    ).filter(PackageLatestReport.version==calias.version)

def store_package_report(pr):
    db_session.add(pr)
    db_session.commit()

#def get_parents(id):
#    return db_session.query(PackageReport).filter(PackageReport.dependemcies.has(PackageReport.id == int(id)))

VIEWS: List[str] = [
    """
CREATE OR REPLACE VIEW latest_reports AS
SELECT * From (
SELECT r.*, row_number() OVER (PARTITION BY package, version ORDER BY scoring_date desc) AS rn
       FROM reports r
     ) r2
WHERE r2.rn = 1
    """
]


def create_views(engine):
    connection = engine.connect()
    for view_command in VIEWS:
        _ = connection.execute(view_command)
    connection.close()


def init_db():
    Model.metadata.create_all(bind=engine)
    create_views(engine)