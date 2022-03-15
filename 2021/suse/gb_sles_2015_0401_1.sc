if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0401.1" );
	script_cve_id( "CVE-2015-0255" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-04-21T09:13:54+0000" );
	script_tag( name: "last_modification", value: "2021-04-21 09:13:54 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_name( "SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2015:0401-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "URL", value: "https://lists.suse.com/pipermail/sle-security-updates/2015-February/001259.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for 'xorg-x11-server'
  package(s) announced via the SUSE-SU-2015:0401-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "'xorg-x11-server' package(s) on SUSE Linux Enterprise Server 12 (ppc64le s390x x86_64)" );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~7.6_1.15.2~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-debuginfo", rpm: "xorg-x11-server-debuginfo~7.6_1.15.2~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-debugsource", rpm: "xorg-x11-server-debugsource~7.6_1.15.2~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra", rpm: "xorg-x11-server-extra~7.6_1.15.2~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra-debuginfo", rpm: "xorg-x11-server-extra-debuginfo~7.6_1.15.2~21.1", rls: "SLES12.0" ) )){
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

