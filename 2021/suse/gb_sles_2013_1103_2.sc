if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1103.2" );
	script_cve_id( "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1988", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2003", "CVE-2013-2063" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 16:35:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1103-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1103-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131103-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2013:1103-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of xorg-x11-libs fixes several integer and buffer overflow issues.

Bug 815451/821663

CVE-2013-1984 CVE-2013-1985 CVE-2013-1986 CVE-2013-1988 CVE-2013-1990 CVE-2013-1991 CVE-2013-1992 CVE-2013-1995 CVE-2013-1996 CVE-2013-1998 CVE-2013-1999 CVE-2013-2000 CVE-2013-2001 CVE-2013-2003 CVE-2013-2063

Security Issues:

 * CVE-2013-1984
>
 * CVE-2013-1985
>
 * CVE-2013-1986
>
 * CVE-2013-1988
>
 * CVE-2013-1990
>
 * CVE-2013-1991
>
 * CVE-2013-1992
>
 * CVE-2013-1995
>
 * CVE-2013-1996
>
 * CVE-2013-1998
>
 * CVE-2013-1999
>
 * CVE-2013-2000
>
 * CVE-2013-2001
>
 * CVE-2013-2003
>
 * CVE-2013-2063
>" );
	script_tag( name: "affected", value: "'xorg-x11-libs' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-32bit", rpm: "xorg-x11-libs-32bit~7.4~8.26.38.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs", rpm: "xorg-x11-libs~7.4~8.26.38.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-x86", rpm: "xorg-x11-libs-x86~7.4~8.26.38.1", rls: "SLES11.0SP3" ) )){
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

