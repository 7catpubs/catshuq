import {
    NavigationAPI,
    type LoginRequest,
    type ExportData,
    type Group,
    type Site,
} from "../src/API/http";

export default {
    async fetch(request: Request, env: Env) {
        const url = new URL(request.url);

        if (url.pathname.startsWith("/api/")) {
            const path = url.pathname.replace("/api/", "");
            const method = request.method;

            try {
                const api = new NavigationAPI(env);

                if (path === "login" && method === "POST") {
                    const loginData = (await request.json()) as LoginInput;

                    const validation = validateLogin(loginData);
                    if (!validation.valid) {
                        return Response.json(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            { status: 400 }
                        );
                    }

                    const result = await api.login(loginData as LoginRequest);
                    return Response.json(result);
                }

                if (path === "test-db" && method === "GET") {
                    try {
                        const result = await env.DB.prepare("SELECT 1 as test").first();
                        return Response.json({
                            success: true,
                            message: "数据库连接成功",
                            result: result,
                        });
                    } catch (error) {
                        return Response.json(
                            {
                                success: false,
                                message: "数据库连接失败",
                                error: error instanceof Error ? error.message : String(error),
                            },
                            { status: 500 }
                        );
                    }
                }

                if (path === "init" && method === "GET") {
                    const initResult = await api.initDB();
                    if (initResult.alreadyInitialized) {
                        return new Response("数据库已经初始化过，无需重复初始化", { status: 200 });
                    }
                    return new Response("数据库初始化成功", { status: 200 });
                }

                const writeOperations = [
                    { pattern: /^groups$/, methods: ["POST"] },
                    { pattern: /^groups\/\d+$/, methods: ["PUT", "DELETE"] },
                    { pattern: /^sites$/, methods: ["POST"] },
                    { pattern: /^sites\/\d+$/, methods: ["PUT", "DELETE"] },
                    { pattern: /^configs\/.*$/, methods: ["PUT", "DELETE"] },
                    { pattern: /^group-orders$/, methods: ["PUT"] },
                    { pattern: /^site-orders$/, methods: ["PUT"] },
                    { pattern: /^import$/, methods: ["POST"] },
                ];

                const isWriteOperation = writeOperations.some(
                    (op) => op.pattern.test(path) && op.methods.includes(method)
                );

                if (isWriteOperation && api.isAuthEnabled()) {
                    const authHeader = request.headers.get("Authorization");
                    if (!authHeader) {
                        return new Response("请先登录", {
                            status: 401,
                            headers: {
                                "WWW-Authenticate": "Bearer",
                            },
                        });
                    }
                    const [authType, token] = authHeader.split(" ");
                    if (authType !== "Bearer" || !token) {
                        return new Response("无效的认证信息", { status: 401 });
                    }
                    const verifyResult = await api.verifyToken(token);
                    if (!verifyResult.valid) {
                        return new Response("认证已过期或无效，请重新登录", { status: 401 });
                    }
                }

                if (path === "groups" && method === "GET") {
                    const groups = await api.getGroups();
                    return Response.json(groups);
                } else if (path.startsWith("groups/") && method === "GET") {
                    const id = parseInt(path.split("/")[1]);
                    if (isNaN(id)) {
                        return Response.json({ error: "无效的ID" }, { status: 400 });
                    }
                    const group = await api.getGroup(id);
                    return Response.json(group);
                } else if (path === "groups" && method === "POST") {
                    const data = (await request.json()) as GroupInput;

                    const validation = validateGroup(data);
                    if (!validation.valid) {
                        return Response.json(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            { status: 400 }
                        );
                    }

                    const result = await api.createGroup(validation.sanitizedData as Group);
                    return Response.json(result);
                } else if (path.startsWith("groups/") && method === "PUT") {
                    const id = parseInt(path.split("/")[1]);
                    if (isNaN(id)) {
                        return Response.json({ error: "无效的ID" }, { status: 400 });
                    }

                    const data = (await request.json()) as Partial<Group>;
                    if (
                        data.name !== undefined &&
                        (typeof data.name !== "string" || data.name.trim() === "")
                    ) {
                        return Response.json(
                            {
                                success: false,
                                message: "分组名称不能为空且必须是字符串",
                            },
                            { status: 400 }
                        );
                    }

                    if (data.order_num !== undefined && typeof data.order_num !== "number") {
                        return Response.json(
                            {
                                success: false,
                                message: "排序号必须是数字",
                            },
                            { status: 400 }
                        );
                    }

                    const result = await api.updateGroup(id, data);
                    return Response.json(result);
                } else if (path.startsWith("groups/") && method === "DELETE") {
                    const id = parseInt(path.split("/")[1]);
                    if (isNaN(id)) {
                        return Response.json({ error: "无效的ID" }, { status: 400 });
                    }

                    const result = await api.deleteGroup(id);
                    return Response.json({ success: result });
                } else if (path === "sites" && method === "GET") {
                    const groupId = url.searchParams.get("groupId");
                    const sites = await api.getSites(groupId ? parseInt(groupId) : undefined);
                    return Response.json(sites);
                } else if (path.startsWith("sites/") && method === "GET") {
                    const id = parseInt(path.split("/")[1]);
                    if (isNaN(id)) {
                        return Response.json({ error: "无效的ID" }, { status: 400 });
                    }

                    const site = await api.getSite(id);
                    return Response.json(site);
                } else if (path === "sites" && method === "POST") {
                    const data = (await request.json()) as SiteInput;

                    const validation = validateSite(data);
                    if (!validation.valid) {
                        return Response.json(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            { status: 400 }
                        );
                    }

                    const result = await api.createSite(validation.sanitizedData as Site);
                    return Response.json(result);
                } else if (path.startsWith("sites/") && method === "PUT") {
                    const id = parseInt(path.split("/")[1]);
                    if (isNaN(id)) {
                        return Response.json({ error: "无效的ID" }, { status: 400 });
                    }

                    const data = (await request.json()) as Partial<Site>;

                    if (data.url !== undefined) {
                        if (typeof data.url !== "string") {
                            return Response.json(
                                { success: false, message: "无效的URL格式" },
                                { status: 400 }
                            );
                        }
                        const paddedUrl = withDefaultProtocol(data.url);
                        try {
                            new URL(paddedUrl);
                        } catch {
                            return Response.json(
                                { success: false, message: "无效的URL格式" },
                                { status: 400 }
                            );
                        }
                        data.url = paddedUrl.trim();
                    }

                    if (data.icon !== undefined && data.icon !== "") {
                        if (typeof data.icon !== "string") {
                            return Response.json(
                                { success: false, message: "无效的图标URL格式" },
                                { status: 400 }
                            );
                        }
                        const paddedIcon = withDefaultProtocol(data.icon);
                        try {
                            new URL(paddedIcon);
                        } catch {
                            return Response.json(
                                { success: false, message: "无效的图标URL格式" },
                                { status: 400 }
                            );
                        }
                        data.icon = paddedIcon.trim();
                    }

                    const result = await api.updateSite(id, data);
                    return Response.json(result);
                } else if (path.startsWith("sites/") && method === "DELETE") {
                    const id = parseInt(path.split("/")[1]);
                    if (isNaN(id)) {
                        return Response.json({ error: "无效的ID" }, { status: 400 });
                    }

                    const result = await api.deleteSite(id);
                    return Response.json({ success: result });
                } else if (path === "group-orders" && method === "PUT") {
                    const data = (await request.json()) as Array<{ id: number; order_num: number }>;

                    if (!Array.isArray(data)) {
                        return Response.json(
                            {
                                success: false,
                                message: "排序数据必须是数组",
                            },
                            { status: 400 }
                        );
                    }

                    for (const item of data) {
                        if (
                            !item.id ||
                            typeof item.id !== "number" ||
                            item.order_num === undefined ||
                            typeof item.order_num !== "number"
                        ) {
                            return Response.json(
                                {
                                    success: false,
                                    message: "排序数据格式无效，每个项目必须包含id和order_num",
                                },
                                { status: 400 }
                            );
                        }
                    }

                    const result = await api.updateGroupOrder(data);
                    return Response.json({ success: result });
                } else if (path === "site-orders" && method === "PUT") {
                    const data = (await request.json()) as Array<{ id: number; order_num: number }>;

                    if (!Array.isArray(data)) {
                        return Response.json(
                            {
                                success: false,
                                message: "排序数据必须是数组",
                            },
                            { status: 400 }
                        );
                    }

                    for (const item of data) {
                        if (
                            !item.id ||
                            typeof item.id !== "number" ||
                            item.order_num === undefined ||
                            typeof item.order_num !== "number"
                        ) {
                            return Response.json(
                                {
                                    success: false,
                                    message: "排序数据格式无效，每个项目必须包含id和order_num",
                                },
                                { status: 400 }
                            );
                        }
                    }

                    const result = await api.updateSiteOrder(data);
                    return Response.json({ success: result });
                } else if (path === "configs" && method === "GET") {
                    const configs = await api.getConfigs();
                    return Response.json(configs);
                } else if (path.startsWith("configs/") && method === "GET") {
                    const key = path.substring("configs/".length);
                    const value = await api.getConfig(key);
                    return Response.json({ key, value });
                } else if (path.startsWith("configs/") && method === "PUT") {
                    const key = path.substring("configs/".length);
                    const data = (await request.json()) as ConfigInput;

                    const validation = validateConfig(data);
                    if (!validation.valid) {
                        return Response.json(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            { status: 400 }
                        );
                    }

                    if (data.value === undefined) {
                        return Response.json(
                            {
                                success: false,
                                message: "配置值必须提供，可以为空字符串",
                            },
                            { status: 400 }
                        );
                    }

                    const result = await api.setConfig(key, data.value);
                    return Response.json({ success: result });
                } else if (path.startsWith("configs/") && method === "DELETE") {
                    const key = path.substring("configs/".length);
                    const result = await api.deleteConfig(key);
                    return Response.json({ success: result });
                } else if (path === "export" && method === "GET") {
                    const data = await api.exportData();
                    return Response.json(data, {
                        headers: {
                            "Content-Disposition": "attachment; filename=navhive-data.json",
                            "Content-Type": "application/json",
                        },
                    });
                } else if (path === "import" && method === "POST") {
                    const data = (await request.json()) as ExportData;

                    if (
                        !data.groups ||
                        !Array.isArray(data.groups) ||
                        !data.sites ||
                        !Array.isArray(data.sites) ||
                        !data.configs ||
                        typeof data.configs !== "object"
                    ) {
                        return Response.json(
                            {
                                success: false,
                                message: "导入数据格式无效",
                            },
                            { status: 400 }
                        );
                    }

                    const result = await api.importData(data as ExportData);
                    return Response.json(result);
                }

                return new Response("API路径不存在", { status: 404 });
            } catch (error) {
                console.error(`API错误: ${error instanceof Error ? error.message : "未知错误"}`);
                return new Response(`处理请求时发生错误`, { status: 500 });
            }
        }

        return new Response("Not Found", { status: 404 });
    },
} satisfies ExportedHandler;

interface Env {
    DB: D1Database;
    AUTH_ENABLED?: string;
    AUTH_USERNAME?: string;
    AUTH_PASSWORD?: string;
    AUTH_SECRET?: string;
}

interface LoginInput {
    username?: string;
    password?: string;
    rememberMe?: boolean;
}

interface GroupInput {
    name?: string;
    order_num?: number;
}

interface SiteInput {
    group_id?: number;
    name?: string;
    url?: string;
    icon?: string;
    description?: string;
    notes?: string;
    order_num?: number;
}

interface ConfigInput {
    value?: string;
}

function validateLogin(data: LoginInput): { valid: boolean; errors?: string[] } {
    const errors: string[] = [];

    if (!data.username || typeof data.username !== "string") {
        errors.push("用户名不能为空且必须是字符串");
    }

    if (!data.password || typeof data.password !== "string") {
        errors.push("密码不能为空且必须是字符串");
    }

    if (data.rememberMe !== undefined && typeof data.rememberMe !== "boolean") {
        errors.push("记住我选项必须是布尔值");
    }

    return { valid: errors.length === 0, errors };
}

function validateGroup(data: GroupInput): {
    valid: boolean;
    errors?: string[];
    sanitizedData?: Group;
} {
    const errors: string[] = [];
    const sanitizedData: Partial<Group> = {};

    if (!data.name || typeof data.name !== "string") {
        errors.push("分组名称不能为空且必须是字符串");
    } else {
        sanitizedData.name = data.name.trim().slice(0, 100);
    }

    if (data.order_num === undefined || typeof data.order_num !== "number") {
        errors.push("排序号必须是数字");
    } else {
        sanitizedData.order_num = data.order_num;
    }

    return {
        valid: errors.length === 0,
        errors,
        sanitizedData: errors.length === 0 ? (sanitizedData as Group) : undefined,
    };
}

function validateSite(data: SiteInput): {
    valid: boolean;
    errors?: string[];
    sanitizedData?: Site;
} {
    const errors: string[] = [];
    const sanitizedData: Partial<Site> = {};

    if (!data.group_id || typeof data.group_id !== "number") {
        errors.push("分组ID必须是数字且不能为空");
    } else {
        sanitizedData.group_id = data.group_id;
    }

    if (!data.name || typeof data.name !== "string") {
        errors.push("站点名称不能为空且必须是字符串");
    } else {
        sanitizedData.name = data.name.trim().slice(0, 100);
    }

    if (!data.url || typeof data.url !== "string") {
        errors.push("URL不能为空且必须是字符串");
    } else {
        try {
            const padded = withDefaultProtocol(data.url);
            new URL(padded);
            sanitizedData.url = padded.trim();
        } catch {
            errors.push("无效的URL格式");
        }
    }

    if (data.icon !== undefined) {
        if (typeof data.icon !== "string") {
            errors.push("图标URL必须是字符串");
        } else if (data.icon) {
            try {
                const paddedIcon = withDefaultProtocol(data.icon);
                new URL(paddedIcon);
                sanitizedData.icon = paddedIcon.trim();
            } catch {
                errors.push("无效的图标URL格式");
            }
        } else {
            sanitizedData.icon = "";
        }
    }

    if (data.description !== undefined) {
        sanitizedData.description =
            typeof data.description === "string"
                ? data.description.trim().slice(0, 500)
                : "";
    }

    if (data.notes !== undefined) {
        sanitizedData.notes =
            typeof data.notes === "string"
                ? data.notes.trim().slice(0, 1000)
                : "";
    }

    if (data.order_num === undefined || typeof data.order_num !== "number") {
        errors.push("排序号必须是数字");
    } else {
        sanitizedData.order_num = data.order_num;
    }

    return {
        valid: errors.length === 0,
        errors,
        sanitizedData: errors.length === 0 ? (sanitizedData as Site) : undefined,
    };
}

function validateConfig(data: ConfigInput): { valid: boolean; errors?: string[] } {
    const errors: string[] = [];

    if (data.value === undefined || typeof data.value !== "string") {
        errors.push("配置值必须是字符串类型");
    }

    return { valid: errors.length === 0, errors };
}

function withDefaultProtocol(raw: string, defaultProto = "https://"): string {
    const s = raw.trim();
    return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) ? s : `${defaultProto}${s}`;
}

interface ExportedHandler {
    fetch(request: Request, env: Env, ctx?: ExecutionContext): Response | Promise<Response>;
}

interface ExecutionContext {
    waitUntil(promise: Promise<any>): void;
    passThroughOnException(): void;
}

interface D1Database {
    prepare(query: string): D1PreparedStatement;
    exec(query: string): Promise<D1Result>;
    batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
}

interface D1PreparedStatement {
    bind(...values: any[]): D1PreparedStatement;
    first<T = unknown>(column?: string): Promise<T | null>;
    run<T = unknown>(): Promise<D1Result<T>>;
    all<T = unknown>(): Promise<D1Result<T>>;
}

interface D1Result<T = unknown> {
    results?: T[];
    success: boolean;
    error?: string;
    meta?: any;
}
