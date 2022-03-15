if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876854" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2019-1010228" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 03:15:00 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-27 02:33:42 +0000 (Fri, 27 Sep 2019)" );
	script_name( "Fedora Update for dcmtk FEDORA-2019-12650a34d8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-12650a34d8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PBKP2O24CTYIANEJTP4TVEPYEVSYV2RX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dcmtk'
  package(s) announced via the FEDORA-2019-12650a34d8 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "DCMTK is a collection of libraries and applications implementing large
parts the DICOM standard. It includes software for examining,
constructing and converting DICOM image files, handling offline media,
sending and receiving images over a network connection, as well as
demonstrative image storage and worklist servers. DCMTK is written
in a mixture of ANSI C and C++.  It comes in complete source code and
is made available as 'open source' software. This package includes
multiple fixes taken from the 'patched DCMTK' project.

Install DCMTK if you are working with DICOM format medical image files." );
	script_tag( name: "affected", value: "'dcmtk' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "dcmtk", rpm: "dcmtk~3.6.2~6.fc30", rls: "FC30" ) )){
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

