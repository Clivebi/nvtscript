if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879663" );
	script_version( "2021-08-24T03:01:09+0000" );
	script_cve_id( "CVE-2021-29510" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 03:01:09 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-25 14:21:00 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 03:20:08 +0000 (Thu, 27 May 2021)" );
	script_name( "Fedora: Security Advisory for python-fastapi (FEDORA-2021-e7fabd81fb)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-e7fabd81fb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UEFWM7DYKD2ZHE7R5YT5EQWJPV4ZKYRB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-fastapi'
  package(s) announced via the FEDORA-2021-e7fabd81fb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "FastAPI is a modern, fast (high-performance), web framework for building APIs
with Python 3.6+ based on standard Python type hints.

The key features are:

   Fast: Very high performance, on par with NodeJS and Go (thanks to Starlette
    and Pydantic). One of the fastest Python frameworks available.

   Fast to code: Increase the speed to develop features by about 200% to 300%.*
   Fewer bugs: Reduce about 40% of human (developer) induced errors.*
   Intuitive: Great editor support. Completion everywhere. Less time
    debugging.
   Easy: Designed to be easy to use and learn. Less time reading docs.
   Short: Minimize code duplication. Multiple features from each parameter
    declaration. Fewer bugs.
   Robust: Get production-ready code. With automatic interactive
    documentation.
   Standards-based: Based on (and fully compatible with) the open standards
    for APIs: OpenAPI (previously known as Swagger) and JSON Schema.

  * estimation based on tests on an internal development team, building production
  applications." );
	script_tag( name: "affected", value: "'python-fastapi' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-fastapi", rpm: "python-fastapi~0.65.1~2.fc34", rls: "FC34" ) )){
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

