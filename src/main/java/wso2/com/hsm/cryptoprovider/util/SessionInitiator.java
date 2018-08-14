package wso2.com.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.*;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class SessionInitiator {
    private static Session[] sessions = null;
    private static Slot[] slotsWithTokens = null;
    private static int[] usersInSlots = null;
    private static ReadWriteLock initiatorLock = new ReentrantReadWriteLock();

    public static Session initiateSession(Module pkcss11Module, String userPin, int slotNo) {
        Session session = null;
        initiatorLock.writeLock().lock();
        if (sessions == null) {
            try {
                slotsWithTokens = pkcss11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
                sessions = new Session[slotsWithTokens.length];
                usersInSlots = new int[slotsWithTokens.length];
            } catch (TokenException e) {
                System.out.println("Slot list retrieving issue: " + e.getMessage());
            }
        }
        if ((sessions.length > slotNo)) {
            if (usersInSlots[slotNo] == 0) {
                Slot slot = slotsWithTokens[slotNo];
                try {
                    Token token = slot.getToken();
                    sessions[slotNo] = token.openSession(Token.SessionType.SERIAL_SESSION,
                            Token.SessionReadWriteBehavior.RW_SESSION, null, null);
                    sessions[slotNo].login(Session.UserType.USER, userPin.toCharArray());
                    usersInSlots[slotNo] += 1;
                } catch (TokenException e) {
                    System.out.println("Session instantiation issue : " + e.getMessage());
                }
            }
            session = sessions[slotNo];
        }
        initiatorLock.writeLock().unlock();
        return session;
    }

    public static boolean closeSession(int slotNo) {
        boolean closed = false;
        initiatorLock.writeLock().lock();
        if (sessions.length > slotNo) {
            try {
                if (usersInSlots[slotNo] > 1) {
                    usersInSlots[slotNo] -= 1;
                } else if (usersInSlots[slotNo] == 1) {
                    sessions[slotNo].closeSession();
                    usersInSlots[slotNo] = 0;
                }
                closed = true;
            } catch (TokenException e) {
                System.out.println("Session closing issue : " + e.getMessage());
            }
        }
        initiatorLock.writeLock().unlock();
        return closed;
    }
}
