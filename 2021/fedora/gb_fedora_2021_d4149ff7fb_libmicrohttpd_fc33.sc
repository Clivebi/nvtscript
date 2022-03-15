if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879519" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2021-3466" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 03:15:00 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-05 03:17:05 +0000 (Wed, 05 May 2021)" );
	script_name( "Fedora: Security Advisory for libmicrohttpd (FEDORA-2021-d4149ff7fb)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-d4149ff7fb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K5NEPVGP3L2CZHLZ4UB44PEILHKPDBOG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmicrohttpd'
  package(s) announced via the FEDORA-2021-d4149ff7fb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GNU libmicrohttpd is a small C library that is supposed to make it
easy to run an HTTP server as part of another application.
Key features that distinguish libmicrohttpd from other projects are:

  * C library: fast and small

  * API is simple, expressive and fully reentrant

  * Implementation is http 1.1 compliant

  * HTTP server can listen on multiple ports

  * Support for IPv6

  * Support for incremental processing of POST data

  * Creates binary of only 25k (for now)

  * Three different threading models" );
	script_tag( name: "affected", value: "'libmicrohttpd' package(s) on Fedora 33." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "libmicrohttpd", rpm: "libmicrohttpd~0.9.73~1.fc33", rls: "FC33" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

