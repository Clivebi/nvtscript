if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871683" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-04 05:41:17 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805", "CVE-2016-6489" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for nettle RHSA-2016:2582-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nettle'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Nettle is a cryptographic library that is
designed to fit easily in almost any context: In cryptographic toolkits for
object-oriented languages, such as C++, Python, or Pike, in applications like lsh
or GnuPG, or even in kernel space.

Security Fix(es):

  * Multiple flaws were found in the way nettle implemented elliptic curve
scalar multiplication. These flaws could potentially introduce
cryptographic weaknesses into nettle's functionality. (CVE-2015-8803,
CVE-2015-8804, CVE-2015-8805)

  * It was found that nettle's RSA and DSA decryption code was vulnerable to
cache-related side channel attacks. An attacker could use this flaw to
recover the private key from a co-located virtual-machine instance.
(CVE-2016-6489)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "nettle on
  Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2582-02" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00018.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "nettle", rpm: "nettle~2.7.1~8.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nettle-debuginfo", rpm: "nettle-debuginfo~2.7.1~8.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nettle-devel", rpm: "nettle-devel~2.7.1~8.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

