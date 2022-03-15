if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877618" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2020-9281", "CVE-2020-9440" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-03-29 03:14:26 +0000 (Sun, 29 Mar 2020)" );
	script_name( "Fedora: Security Advisory for ckeditor (FEDORA-2020-261449d821)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-261449d821" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M4HHYQ6N452XTCIROFMJOTYEUWSB6FR4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ckeditor'
  package(s) announced via the FEDORA-2020-261449d821 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CKEditor is a text editor to be used inside web pages. It&#39, s a WYSIWYG editor,
which means that the text being edited on it looks as similar as possible to
the results users have when publishing it. It brings to the web common editing
features found on desktop editing applications like Microsoft Word and
OpenOffice." );
	script_tag( name: "affected", value: "'ckeditor' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "ckeditor", rpm: "ckeditor~4.14.0~1.fc30", rls: "FC30" ) )){
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

