if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877686" );
	script_version( "2021-07-19T11:00:51+0000" );
	script_cve_id( "CVE-2020-5247", "CVE-2020-5249" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-09 17:15:00 +0000 (Thu, 09 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-12 03:15:53 +0000 (Sun, 12 Apr 2020)" );
	script_name( "Fedora: Security Advisory for rubygem-puma (FEDORA-2020-a3f26a9387)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-a3f26a9387" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NJ3LL5F5QADB6LM46GXZETREAKZMQNRD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-puma'
  package(s) announced via the FEDORA-2020-a3f26a9387 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A simple, fast, threaded, and highly concurrent HTTP 1.1 server for
Ruby/Rack applications." );
	script_tag( name: "affected", value: "'rubygem-puma' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "rubygem-puma", rpm: "rubygem-puma~4.3.3~1.fc32", rls: "FC32" ) )){
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

