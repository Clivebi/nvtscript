if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878201" );
	script_version( "2020-09-28T14:47:37+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-09-28 14:47:37 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-08-18 03:07:04 +0000 (Tue, 18 Aug 2020)" );
	script_name( "Fedora: Security Advisory for wob (FEDORA-2020-4def6ebb77)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-4def6ebb77" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/STB4W47B3CCDE7IHWAGOBC7FH6CIULWT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wob'
  package(s) announced via the FEDORA-2020-4def6ebb77 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A lightweight overlay volume/backlight/progress/anything bar for
Wayland." );
	script_tag( name: "affected", value: "'wob' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "wob", rpm: "wob~0.10~1.fc31", rls: "FC31" ) )){
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

