if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876704" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-1010238" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-14 15:41:00 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-08-21 02:25:36 +0000 (Wed, 21 Aug 2019)" );
	script_name( "Fedora Update for pango FEDORA-2019-547be4a683" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-547be4a683" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/D6HWAHXJ2ZXINYMANHPFDDCJFWUQ57M4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'pango' package(s) announced via the FEDORA-2019-547be4a683 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Pango is a library for laying out and
  rendering of text, with an emphasis on internationalization. Pango can be used
  anywhere that text layout is needed, though most of the work on Pango so far
  has been done in the context of the GTK+ widget toolkit. Pango forms the core
  of text and font handling for GTK+.

Pango is designed to be modular, the core Pango layout engine can be used
with different font backends.

The integration of Pango with Cairo provides a complete solution with high
quality text handling and graphics rendering." );
	script_tag( name: "affected", value: "'pango' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "pango", rpm: "pango~1.43.0~4.fc30", rls: "FC30" ) )){
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

