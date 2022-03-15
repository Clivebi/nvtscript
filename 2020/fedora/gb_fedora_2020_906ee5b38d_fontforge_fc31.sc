if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877510" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2020-5395" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-22 01:15:00 +0000 (Wed, 22 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-02-28 04:05:40 +0000 (Fri, 28 Feb 2020)" );
	script_name( "Fedora: Security Advisory for fontforge (FEDORA-2020-906ee5b38d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-906ee5b38d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MH6PKVQLBKIO7LQPDXB3MKI5I6AMDCN6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fontforge'
  package(s) announced via the FEDORA-2020-906ee5b38d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "FontForge (former PfaEdit) is a font editor for outline and bitmap
fonts. It supports a range of font formats, including PostScript
(ASCII and binary Type 1, some Type 3 and Type 0), TrueType, OpenType
(Type2) and CID-keyed fonts." );
	script_tag( name: "affected", value: "'fontforge' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "fontforge", rpm: "fontforge~20190801~6.fc31", rls: "FC31" ) )){
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

