if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120543" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:06 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-258)" );
	script_tag( name: "insight", value: "Multiple buffer underflows in the XFS implementation in the Linux kernel through 3.12.1 allow local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging the CAP_SYS_ADMIN capability for a (1) XFS_IOC_ATTRLIST_BY_HANDLE or (2) XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted length value, related to the xfs_attrlist_by_handle function in fs/xfs/xfs_ioctl.c and the xfs_compat_attrlist_by_handle function in fs/xfs/xfs_ioctl32.c." );
	script_tag( name: "solution", value: "Run yum update kernel to update your system. You will need to reboot your system in order for the new kernel to be running." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-258.html" );
	script_cve_id( "CVE-2013-6382" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-debuginfo", rpm: "kernel-tools-debuginfo~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo-common-i686", rpm: "kernel-debuginfo-common-i686~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.4.73~64.112.amzn1", rls: "AMAZON" ) )){
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

