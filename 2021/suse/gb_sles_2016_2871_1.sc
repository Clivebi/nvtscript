if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2871.1" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-09 15:00:22 +0000 (Wed, 09 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2871-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2871-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162871-1/" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/native-1.1-doc/miscellaneous/changelog.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtcnative-1-0' package(s) announced via the SUSE-SU-2016:2871-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libtcnative-1-0 fixes the following issues:
- Upgrade to libtcnative-1.1.34 (bugfix release) (bsc#1004455) See
 [link moved to references]
 * Unconditionally disable export Ciphers.
 * Improve ephemeral key handling for DH and ECDH. Parameter strength is
 by default derived from the certificate key strength.
 * APIs SSL.generateRSATempKey() and SSL.loadDSATempKey() are no longer
 supported.
 * Various bugfixes." );
	script_tag( name: "affected", value: "'libtcnative-1-0' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libtcnative-1-0", rpm: "libtcnative-1-0~1.1.34~12.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtcnative-1-0-debuginfo", rpm: "libtcnative-1-0-debuginfo~1.1.34~12.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtcnative-1-0-debugsource", rpm: "libtcnative-1-0-debugsource~1.1.34~12.1", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libtcnative-1-0", rpm: "libtcnative-1-0~1.1.34~12.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtcnative-1-0-debuginfo", rpm: "libtcnative-1-0-debuginfo~1.1.34~12.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtcnative-1-0-debugsource", rpm: "libtcnative-1-0-debugsource~1.1.34~12.1", rls: "SLES12.0SP2" ) )){
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

