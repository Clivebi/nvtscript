if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879764" );
	script_version( "2021-08-20T12:01:13+0000" );
	script_cve_id( "CVE-2021-31618" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 12:01:13 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-20 03:16:58 +0000 (Sun, 20 Jun 2021)" );
	script_name( "Fedora: Security Advisory for mod_http2 (FEDORA-2021-051639aad4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-051639aad4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2NKJ3ZA3FTSZ2QBBPKS6BYGAWYRABNQQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod_http2'
  package(s) announced via the FEDORA-2021-051639aad4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The mod_h2 Apache httpd module implements the HTTP2 protocol (h2+h2c) on
top of libnghttp2 for httpd 2.4 servers." );
	script_tag( name: "affected", value: "'mod_http2' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "mod_http2", rpm: "mod_http2~1.15.19~1.fc33", rls: "FC33" ) )){
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

