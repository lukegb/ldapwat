from zope.interface import implements

from twisted.internet.protocol import ServerFactory
from twisted.internet.ssl import DefaultOpenSSLContextFactory, SSL
from twisted.python.components import registerAdapter
from twisted.python import failure
from twisted.python.modules import getModule
from twisted.application import service, internet
from twisted.internet import protocol, reactor, defer, ssl

from ldaptor.protocols.ldap.ldapserver import LDAPServer
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols import pureber, pureldap
from ldaptor import entry, entryhelpers, interfaces, inmemory

from passlib.utils.pbkdf2 import pbkdf2

from sqlalchemy import Table, Column, Integer, String, select, create_engine, MetaData

# HACK HACK HACK
import sys; sys.setrecursionlimit(10000)
import os

COUNTRY = ('dc=org', {'objectclass': ['dcObject'], 'dc':['org']})
ORG = ('dc=spongepowered', {'objectclass':['dcObject'], 'dc':['spongepowered']})
PEOPLE = ('ou=people', {'ou':['people'], 'objectclass':['organizationalunit']})

class DynamicPersonEntry(entry.BaseLDAPEntry,
                entryhelpers.DiffTreeMixin,
                entryhelpers.MatchMixin,
                entryhelpers.SearchByTreeWalkingMixin,
                ):
    implements(interfaces.IConnectedLDAPEntry)

    def __init__(self, user, parent):
        super(DynamicPersonEntry, self).__init__(*self._construct_entry(user, parent))
        self._parent = parent
        self._user = user

    def _construct_entry(self, user, parent):
        dn = 'uid={}'.format(user.username) + ',' + str(parent.dn) 
        attributes = {
            'objectClass': ['people', 'inetOrgPerson'],
            'cn': [user.full_name,],
            'sn': [user.full_name,],
            'uid': [user.username,],
            'mail': [user.email,],
        }
        return dn, attributes

    def parent(self):
        return self._parent

    def children(self, callback=None):
        if callback is None:
            return defer.succeed([])
        else:
            return defer.succeed(None)

    def subtree(self, callback=None):
        if callback is None:
            return defer.succeed([self])
        else:
            callback(self)
            return defer.succeed(None)

    def lookup(self, dn):
        if dn == self.dn:
            return defer.succeed(self)

        return defer.fail(failure.Failure(ldaperrors.LDAPNoSuchObject(dn)))

    def fetch(self, *attributes):
        return defer.succeed(self)

    def bind(self, password):
        return defer.maybeDeferred(self._bind, password)

    def _bind(self, password):
        if self._user.authenticate(password):
            return defer.succeed(self)
        raise ldaperrors.LDAPInvalidCredentials

class DynamicPeopleTreeEntry(entry.BaseLDAPEntry,
                entryhelpers.DiffTreeMixin,
                entryhelpers.SubtreeFromChildrenMixin,
                entryhelpers.MatchMixin,
                entryhelpers.SearchByTreeWalkingMixin,
                ):
    implements(interfaces.IConnectedLDAPEntry)

    def __init__(self, dn, attributes, user_repo):
        super(DynamicPeopleTreeEntry, self).__init__(dn, attributes)
        self._user_repo = user_repo
        self._parent = None

    def parent(self):
        return self._parent

    def children(self, callback=None):
        if callback is None:
            return defer.succeed(list(self._children()))
        else:
            for c in self._children():
                callback(c)
            return defer.succeed(None)

    def _lookup(self, dn):
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn)

        if dn == self.dn:
            return defer.succeed(self)

        try:
            return self._child(dn).lookup(dn)
        except:
            raise ldaperrors.LDAPNoSuchObject(dn)

    def lookup(self, dn):
        return defer.maybeDeferred(self._lookup, dn)

    def fetch(self, *attributes):
        return defer.succeed(self)

    def _spawn_child(self, user):
        if user is None:
            return None

        return DynamicPersonEntry(user, self)

    def _children(self):
        for child_entry in self._user_repo.fetch_all():
            yield self._spawn_child(child_entry)

    def _child(self, dn):
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn)

        its = list(dn.split())
        mine = list(self.dn.split())
        its = its[:-len(mine)]

        its_next = its[-1]
        its_next_str = str(its_next)
        if not its_next_str.startswith('uid=') or '+' in its_next_str:
            raise ldaperrors.LDAPNoSuchObject(dn)

        username = its_next_str[4:]

        return self._spawn_child(self._user_repo.fetch(username))

    def search(self,
               filterText=None,
               filterObject=None,
               attributes=(),
               scope=None,
               derefAliases=None,
               sizeLimit=0,
               timeLimit=0,
               typesOnly=0,
               callback=None):
        if filterObject is None and filterText is not None:
            filterObject = ldapfilter.parseFilter(fileText)
        elif filterObject is not None and filterText is not None:
            filterObject = pureldap.LDAPFilter_and((ldapfilter.parseFilter(filterText), filterObject))

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree

        if scope == pureldap.LDAP_SCOPE_wholeSubtree or scope == pureldap.LDAP_SCOPE_singleLevel:
            try:
                res = self._fast_search(filterObject)
                return defer.succeed(res)
            except:
                pass # try slow path

        return super(DynamicPeopleTreeEntry, self).search(filterText, filterObject, attributes, scope, derefAliases, sizeLimit, timeLimit, typesOnly, callback)

    def _fast_search(self, filterObject):
        if not isinstance(filterObject, pureldap.LDAPFilter_equalityMatch):
            raise Exception("can't handle non equality")
        elif filterObject.attributeDesc.value != 'uid':
            raise Exception("can't handle non uid")

        look_for = filterObject.assertionValue.value
        u = self._spawn_child(self._user_repo.fetch(username))
        if u is None:
            return []
        return [u]


class Tree(object):
    def __init__(self, user_repo):
        self.db = self.build_tree(user_repo)

    def build_tree(self, user_repo):
        root = inmemory.ReadOnlyInMemoryLDAPEntry(COUNTRY[0], COUNTRY[1])
        org = root.addChild(ORG[0], ORG[1])
        people = DynamicPeopleTreeEntry(PEOPLE[0] + ',' + str(org.dn), PEOPLE[1], user_repo)

        # HACK HACK HACK
        people._parent = org
        org._children.append(people)

        return root

metadata = MetaData()
users = Table('users', metadata,
    Column('id', Integer, primary_key=True),
    Column('name', String),
    Column('username', String),
    Column('email', String),
    Column('password_hash', String),
    Column('salt', String),
)

class TestUser(object):
    def __init__(self, record):
        self._record = record

    @property
    def username(self):
        return self._record['username'].encode('utf-8')

    @property
    def full_name(self):
        return self._record['name'].encode('utf-8')

    @property
    def email(self):
        return self._record['email'].encode('utf-8')

    def authenticate(self, password):
        return self._record['password'] == password

class TestUserRepo(object):
    def __init__(self, records):
        self.records = dict([(k, TestUser(v)) for (k, v) in records.items()])

    def fetch(self, username):
        return self.records.get(username)

    def fetch_all(self):
        return self.records.values()

class ProductionUser(object):
    def __init__(self, record):
        self._record = record

    @property
    def username(self):
        return self._record[users.c.username].encode('utf-8')

    @property
    def full_name(self):
        return self._record[users.c.name].encode('utf-8')

    @property
    def email(self):
        return self._record[users.c.email].encode('utf-8')

    def authenticate(self, password):
        calc = pbkdf2(password, str(self._record[users.c.salt]), 64000, None, 'hmac-sha256').encode('hex')
        expc = self._record[users.c.password_hash]
        print calc, expc
        return calc == expc

class ProductionUserRepo(object):
    def __init__(self, engine):
        self.engine = engine
        self.conn = engine.connect()

    def fetch(self, username):
        result = self.conn.execute(select([users]).where(users.c.username == username)).fetchone()
        if result is None:
            return None
        return ProductionUser(result)

    def fetch_all(self):
        result = self.conn.execute(select([users]))
        for row in result:
            yield ProductionUser(row)

if 'LDAPWAT_DB_URL' in os.environ:
    repo = ProductionUserRepo(create_engine(os.environ.get('LDAPWAT_DB_URL'), encoding='utf-8', echo=True))
elif 'LDAPWAT_USE_TEST' in os.environ:
    repo = TestUserRepo({
        'lukegb': {
            'username': 'lukegb',
            'password': 'test123',
            'name': 'Luke GB',
            'email': 'test@test.lukegb.com',
        },
    })
else:
    print "NOPE"
    sys.exit(1)

tree = Tree(repo)

class LDAPServerFactory(ServerFactory):
    protocol = LDAPServer
    def __init__(self, root):
        self.root = root

registerAdapter(lambda x: x.root,
            LDAPServerFactory,
            interfaces.IConnectedLDAPEntry)

class ChainedOpenSSLContextFactory(DefaultOpenSSLContextFactory):
    def __init__(self, privateKeyFileName, certificateChainFileName,
                 sslmethod=SSL.TLSv1_METHOD):
        """
        @param privateKeyFileName: Name of a file containing a private key
        @param certificateChainFileName: Name of a file containing a certificate chain
        @param sslmethod: The SSL method to use
        """
        self.privateKeyFileName = privateKeyFileName
        self.certificateChainFileName = certificateChainFileName
        self.sslmethod = sslmethod
        self.cacheContext()
    
    def cacheContext(self):
        ctx = SSL.Context(self.sslmethod)
        ctx.use_certificate_chain_file(self.certificateChainFileName)
        ctx.use_privatekey_file(self.privateKeyFileName)
        self._context = ctx

factory = LDAPServerFactory(tree.db)
application = service.Application("ldaptor-server")
myService = service.IServiceCollection(application)
reactor.listenTCP(3389, factory)
reactor.run()
