if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879274" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2021-3443" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-30 16:52:00 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-25 04:07:22 +0000 (Thu, 25 Mar 2021)" );
	script_name( "Fedora: Security Advisory for jasper (FEDORA-2021-26cb56b3cb)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-26cb56b3cb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FA3CJIEYQGFLPOD3LDVQW7JN3TSJPCZR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper'
  package(s) announced via the FEDORA-2021-26cb56b3cb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains an implementation of the image compression
standard JPEG-2000, Part 1. It consists of tools for conversion to and
from the JP2 and JPC formats." );
	script_tag( name: "affected", value: "'jasper' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "jasper", rpm: "jasper~2.0.26~2.fc32", rls: "FC32" ) )){
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

