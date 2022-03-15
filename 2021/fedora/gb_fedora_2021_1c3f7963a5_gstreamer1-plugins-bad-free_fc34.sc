if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879740" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-30473", "CVE-2021-30475" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-17 16:58:00 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 03:24:36 +0000 (Thu, 17 Jun 2021)" );
	script_name( "Fedora: Security Advisory for gstreamer1-plugins-bad-free (FEDORA-2021-1c3f7963a5)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-1c3f7963a5" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FIELJQTRGQZGHBEJDQ7CJYI4DFNWMP74" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer1-plugins-bad-free'
  package(s) announced via the FEDORA-2021-1c3f7963a5 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GStreamer is a streaming media framework, based on graphs of elements which
operate on media data.

This package contains plug-ins that aren&#39, t tested well enough, or the code
is not of good enough quality." );
	script_tag( name: "affected", value: "'gstreamer1-plugins-bad-free' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1-plugins-bad-free", rpm: "gstreamer1-plugins-bad-free~1.19.1~2.fc34", rls: "FC34" ) )){
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

