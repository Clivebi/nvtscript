if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878756" );
	script_version( "2021-07-20T11:00:49+0000" );
	script_cve_id( "CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27845" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-20 11:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-12-22 04:13:13 +0000 (Tue, 22 Dec 2020)" );
	script_name( "Fedora: Security Advisory for openjpeg2 (FEDORA-2020-3e00413763)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-3e00413763" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/THY4LKGUS3D4XE5YHKLMTPVLURQ7OV57" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the FEDORA-2020-3e00413763 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJPEG library is an open-source JPEG 2000 library developed in order to
promote the use of JPEG 2000.

This package contains

  * JPEG 2000 codec compliant with the Part 1 of the standard (Class-1 Profile-1
  compliance).

  * JP2 (JPEG 2000 standard Part 2 - Handling of JP2 boxes and extended multiple
  component transforms for multispectral and hyperspectral imagery)" );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2", rpm: "openjpeg2~2.3.1~10.fc33", rls: "FC33" ) )){
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
