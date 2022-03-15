if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883242" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-11521", "CVE-2020-11523", "CVE-2020-11524" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 02:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-02 03:00:57 +0000 (Tue, 02 Jun 2020)" );
	script_name( "CentOS: Security Advisory for freerdp (CESA-2020:2334)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:2334" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-June/035742.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp'
  package(s) announced via the CESA-2020:2334 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
released under the Apache license. The xfreerdp client can connect to RDP
servers such as Microsoft Windows machines, xrdp, and VirtualBox.

Security Fix(es):

  * freerdp: Out-of-bounds write in planar.c (CVE-2020-11521)

  * freerdp: Integer overflow in region.c (CVE-2020-11523)

  * freerdp: Out-of-bounds write in interleaved.c (CVE-2020-11524)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'freerdp' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "freerdp", rpm: "freerdp~2.0.0~4.rc4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-devel", rpm: "freerdp-devel~2.0.0~4.rc4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-libs", rpm: "freerdp-libs~2.0.0~4.rc4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwinpr", rpm: "libwinpr~2.0.0~4.rc4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwinpr-devel", rpm: "libwinpr-devel~2.0.0~4.rc4.el7_8", rls: "CentOS7" ) )){
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

