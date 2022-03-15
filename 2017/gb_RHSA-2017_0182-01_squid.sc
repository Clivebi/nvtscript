if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871750" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-25 05:41:58 +0100 (Wed, 25 Jan 2017)" );
	script_cve_id( "CVE-2016-10002" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for squid RHSA-2017:0182-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

Security Fix(es):

  * It was found that squid did not properly remove connection specific
headers when answering conditional requests using a cached request. A
remote attacker could send a specially crafted request to an HTTP server
via the squid proxy and steal private data from other connections.
(CVE-2016-10002)" );
	script_tag( name: "affected", value: "squid on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:0182-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-January/msg00040.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "squid", rpm: "squid~3.5.20~2.el7_3.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~3.5.20~2.el7_3.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "squid-migration-script", rpm: "squid-migration-script~3.5.20~2.el7_3.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

