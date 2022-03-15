if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879658" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2021-29510" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-25 14:21:00 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 03:20:04 +0000 (Thu, 27 May 2021)" );
	script_name( "Fedora: Security Advisory for python-starlette (FEDORA-2021-e7fabd81fb)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-e7fabd81fb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3II6YFPCDUFLD44X7EGU5AHI2BIGC74C" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-starlette'
  package(s) announced via the FEDORA-2021-e7fabd81fb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Starlette is a lightweight ASGI framework/toolkit, which is ideal for building
high performance asyncio services.

It is production-ready, and gives you the following:

  * Seriously impressive performance.

  * WebSocket support.

  * GraphQL support.

  * In-process background tasks.

  * Startup and shutdown events.

  * Test client built on requests.

  * CORS, GZip, Static Files, Streaming responses.

  * Session and Cookie support.

  * 100% test coverage.

  * 100% type annotated codebase.

  * Zero hard dependencies." );
	script_tag( name: "affected", value: "'python-starlette' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "python-starlette", rpm: "python-starlette~0.14.2~6.fc34", rls: "FC34" ) )){
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

