if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877047" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2019-12211", "CVE-2019-12213" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-03 05:15:00 +0000 (Sat, 03 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-11-30 03:38:59 +0000 (Sat, 30 Nov 2019)" );
	script_name( "Fedora Update for mingw-freeimage FEDORA-2019-76f546b7b8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-76f546b7b8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VZ7KBYPPNRMX7RRWVJSX4T63E3TFB6TG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-freeimage'
  package(s) announced via the FEDORA-2019-76f546b7b8 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows freeimage library." );
	script_tag( name: "affected", value: "'mingw-freeimage' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "mingw-freeimage", rpm: "mingw-freeimage~3.18.0~7.fc30", rls: "FC30" ) )){
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

