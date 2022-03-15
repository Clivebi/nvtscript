if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871712" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-04 05:43:43 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-2572", "CVE-2016-3948" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for squid RHSA-2016:2600-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

The following packages have been upgraded to a newer upstream version:
squid (3.5.20). (BZ#1273942, BZ#1349775)

Security Fix(es):

  * Incorrect boundary checks were found in the way squid handled headers in
HTTP responses, which could lead to an assertion failure. A malicious HTTP
server could use this flaw to crash squid using a specially crafted HTTP
response. (CVE-2016-2569, CVE-2016-2570)

  * It was found that squid did not properly handle errors when failing to
parse an HTTP response, possibly leading to an assertion failure. A
malicious HTTP server could use this flaw to crash squid using a specially
crafted HTTP response. (CVE-2016-2571, CVE-2016-2572)

  * An incorrect boundary check was found in the way squid handled the Vary
header in HTTP responses, which could lead to an assertion failure. A
malicious HTTP server could use this flaw to crash squid using a specially
crafted HTTP response. (CVE-2016-3948)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "squid on
  Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2600-02" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00036.html" );
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
	if(( res = isrpmvuln( pkg: "squid", rpm: "squid~3.5.20~2.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~3.5.20~2.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "squid-migration-script", rpm: "squid-migration-script~3.5.20~2.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

