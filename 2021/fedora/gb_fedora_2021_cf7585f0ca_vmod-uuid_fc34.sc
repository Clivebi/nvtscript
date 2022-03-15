if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879841" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2021-36740" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-05 15:02:00 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-27 03:22:58 +0000 (Tue, 27 Jul 2021)" );
	script_name( "Fedora: Security Advisory for vmod-uuid (FEDORA-2021-cf7585f0ca)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-cf7585f0ca" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MA257Z423D5NEDRCLWTFWWRC3D4IWWYC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vmod-uuid'
  package(s) announced via the FEDORA-2021-cf7585f0ca advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "UUID Varnish vmod used to generate a uuid, including versions 1, 3, 4 and 5
as specified in RFC 4122. See the RFC for details about the various versions." );
	script_tag( name: "affected", value: "'vmod-uuid' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "vmod-uuid", rpm: "vmod-uuid~1.8~4.fc34", rls: "FC34" ) )){
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

