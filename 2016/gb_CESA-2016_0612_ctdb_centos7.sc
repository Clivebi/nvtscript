if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882463" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-14 05:19:41 +0200 (Thu, 14 Apr 2016)" );
	script_cve_id( "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for ctdb CESA-2016:0612 centos7" );
	script_tag( name: "summary", value: "Check the version of ctdb" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Samba is an open-source implementation of
the Server Message Block (SMB) protocol and the related Common Internet File
System (CIFS) protocol, which allow PC-compatible machines to share files,
printers, and various information.

The following packages have been upgraded to a newer upstream version:
Samba (4.2.10). Refer to the Release Notes listed in the References section
for a complete list of changes.

Security Fix(es):

  * Multiple flaws were found in Samba's DCE/RPC protocol implementation. A
remote, authenticated attacker could use these flaws to cause a denial of
service against the Samba server (high CPU load or a crash) or, possibly,
execute arbitrary code with the permissions of the user running Samba
(root). This flaw could also be used to downgrade a secure DCE/RPC
connection by a man-in-the-middle attacker taking control of an Active
Directory (AD) object and compromising the security of a Samba Active
Directory Domain Controller (DC). (CVE-2015-5370)

Note: While Samba packages as shipped in Red Hat Enterprise Linux do not
support running Samba as an AD DC, this flaw applies to all roles Samba
implements.

  * A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local Security
Authority (Domain Policy) Remote Protocol (MS-LSAD). Any authenticated
DCE/RPC connection that a client initiates against a server could be used
by a man-in-the-middle attacker to impersonate the authenticated user
against the SAMR or LSA service on the server. As a result, the attacker
would be able to get read/write access to the Security Account Manager
database, and use this to reveal all passwords or any other potentially
sensitive information in that database. (CVE-2016-2118)

  * Several flaws were found in Samba's implementation of NTLMSSP
authentication. An unauthenticated, man-in-the-middle attacker could use
this flaw to clear the encryption and integrity flags of a connection,
causing data to be transmitted in plain text. The attacker could also force
the client or server into sending data in plain text even if encryption was
explicitly requested for that connection. (CVE-2016-2110)

  * It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a spoofed
computer name. A remote attacker able to observe network traffic could use
this flaw to obtain session-related information about the spoofed machine.
(CVE-2016-2111)

  * It was found that Samba's LDAP implementation did not enforce integrity
protection for LDAP connections. A man-in-the-middle attacker could use
th ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "ctdb on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0612" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-April/021828.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "ctdb", rpm: "ctdb~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ctdb-devel", rpm: "ctdb-devel~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ctdb-tests", rpm: "ctdb-tests~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client-libs", rpm: "samba-client-libs~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common-libs", rpm: "samba-common-libs~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-dc", rpm: "samba-dc~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-dc-libs", rpm: "samba-dc-libs~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-devel", rpm: "samba-devel~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-pidl", rpm: "samba-pidl~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-python", rpm: "samba-python~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test", rpm: "samba-test~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test-devel", rpm: "samba-test-devel~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test-libs", rpm: "samba-test-libs~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-vfs-glusterfs", rpm: "samba-vfs-glusterfs~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-krb5-locator", rpm: "samba-winbind-krb5-locator~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-modules", rpm: "samba-winbind-modules~4.2.10~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

