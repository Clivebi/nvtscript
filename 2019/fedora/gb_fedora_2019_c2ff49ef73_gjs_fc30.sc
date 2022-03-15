if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876531" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-11707", "CVE-2019-11708" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-15 18:15:00 +0000 (Thu, 15 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-06-25 02:17:35 +0000 (Tue, 25 Jun 2019)" );
	script_name( "Fedora Update for gjs FEDORA-2019-c2ff49ef73" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-c2ff49ef73" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZS2X4UWVWTNTNWOCAJYQO77GGSSI3H6K" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'gjs' package(s) announced via the FEDORA-2019-c2ff49ef73 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Gjs allows using GNOME libraries from Javascript.
  It&#39, s based on the Spidermonkey Javascript engine from Mozilla and the GObject
  introspection framework." );
	script_tag( name: "affected", value: "'gjs' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "gjs", rpm: "gjs~1.56.2~4.fc30", rls: "FC30" ) )){
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

