// 在页面加载时动态注入顶部导航，保持各模板统一
(function(){
    function loadHeader(){
        fetch('/static/partials/header.html')
            .then(r => r.text())
            .then(html => {
                const el = document.getElementById('site-header');
                if(!el) return;
                el.innerHTML = html;

                // 设置当前激活的菜单样式
                const path = location.pathname || '/';
                document.querySelectorAll('.nav-menu a').forEach(a => a.classList.remove('active'));
                if(path === '/' || path === '/index.html'){
                    const elHome = document.querySelector('.nav-home'); if(elHome) elHome.classList.add('active');
                } else if(path.startsWith('/gallery')){
                    const elG = document.querySelector('.nav-gallery'); if(elG) elG.classList.add('active');
                } else if(path.startsWith('/amazon-ad-management') || path.startsWith('/amazon-ad-subtype-management')){
                    const elAd = document.querySelector('.nav-amazon-ad'); if(elAd) elAd.classList.add('active');
                } else if(path.startsWith('/product-management') || path.startsWith('/category-management') || path.startsWith('/fabric-management') || path.startsWith('/feature-management') || path.startsWith('/material-management') || path.startsWith('/certification-management') || path.startsWith('/order-product-management') || path.startsWith('/shop-brand-management')){
                    const elP = document.querySelector('.nav-product'); if(elP) elP.classList.add('active');
                } else if(path.startsWith('/sales-product-management') || path.startsWith('/parent-management')){
                    const elS = document.querySelector('.nav-sales'); if(elS) elS.classList.add('active');
                } else if(path.startsWith('/about')){
                    const elA = document.querySelector('.nav-about'); if(elA) elA.classList.add('active');
                }
            })
            .catch(err => console.error('Load header failed', err));
    }

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', loadHeader);
    } else {
        loadHeader();
    }
})();